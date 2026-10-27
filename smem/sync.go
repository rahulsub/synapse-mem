package smem

import (
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ImportReport describes what an import accepted and refused.
type ImportReport struct {
	Accepted    int      `json:"accepted"`
	Skipped     int      `json:"skipped"` // already present
	Rejected    []string `json:"rejected"`
	Rebuilt     bool     `json:"rebuilt"`     // projections were replayed because order-sensitive events arrived late
	Flags       []Flag   `json:"flags"`       // records marked suspect locally as a result
	Quarantined int      `json:"quarantined"` // accepted but signed by an untrusted key, so not projected
	Clamped     int      `json:"clamped"`     // backdated beyond sync.max_backdate; projected at the clamped time
}

// Import merges events from other replicas. Each feed is verified on its
// own: contiguous rseq, intact chain, valid hash and signature. A feed is
// accepted up to its first bad event; nothing after a bad event is trusted.
// A different event at an rseq we already have is a fork and is refused.
//
// Time is bounded: an event dated more than sync.max_future_skew ahead of
// the local clock is refused (it would drag every later local timestamp
// forward), a feed whose time runs backwards is refused, and an event older
// than sync.max_backdate is kept as signed but projected as if it happened
// max_backdate ago, so it can't rewrite what as-of queries say was known.
func (e *Engine) Import(evs []Event) (*ImportReport, error) {
	rep := &ImportReport{}
	pol := e.Policy.Sync
	now := e.Now().UnixMilli()
	emitted, err := e.write(func(w *wtx) error {
		keys, err := w.publicKeys()
		if err != nil {
			return err
		}
		// Registrations can arrive in the same batch as the events they sign.
		for _, ev := range evs {
			if ev.Type != evKeyRegistered {
				continue
			}
			var p keyRegistered
			if json.Unmarshal(ev.Payload, &p) != nil {
				continue
			}
			if pub, err := decodePublicKey(p.PublicKey); err == nil && keyID(pub) == p.KeyID && ev.KeyID == p.KeyID {
				if _, ok := keys[p.KeyID]; !ok {
					keys[p.KeyID] = keyInfo{pub: pub, actor: p.Actor}
				}
			}
		}

		last, err := scanEvent(w.tx.QueryRow(`SELECT ` + eventCols + ` FROM events ORDER BY at DESC, replica DESC, rseq DESC LIMIT 1`))
		haveLast := err == nil
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}

		feeds := map[string][]Event{}
		for _, ev := range evs {
			feeds[ev.Replica] = append(feeds[ev.Replica], ev)
		}
		replicas := make([]string, 0, len(feeds))
		for r := range feeds {
			replicas = append(replicas, r)
		}
		sort.Strings(replicas)

		var accepted []Event
		for _, r := range replicas {
			feed := feeds[r]
			if r == w.e.replica {
				rep.Skipped += len(feed)
				continue
			}
			sort.Slice(feed, func(i, j int) bool { return feed[i].RSeq < feed[j].RSeq })
			headSeq, headHash, headAt, err := w.head(r)
			if err != nil {
				return err
			}
			for _, ev := range feed {
				reject := func(why string) { rep.Rejected = append(rep.Rejected, fmt.Sprintf("%s/%d: %s", r, ev.RSeq, why)) }
				if ev.RSeq <= headSeq {
					var have string
					if err := w.tx.QueryRow(`SELECT hash FROM events WHERE replica = ? AND rseq = ?`, r, ev.RSeq).Scan(&have); err != nil {
						return err
					}
					if have != ev.Hash {
						reject("fork: differs from the event we already have at this position")
						break
					}
					rep.Skipped++
					continue
				}
				if ev.RSeq != headSeq+1 {
					reject(fmt.Sprintf("gap: expected rseq %d", headSeq+1))
					break
				}
				if ev.Prev != headHash {
					reject("chain broken: prev does not match the preceding event")
					break
				}
				if ev.At > now+pol.MaxFutureSkew.D().Milliseconds() {
					reject(fmt.Sprintf("dated %s, in the future; retry once the clocks agree", fromMs(ev.At).Format(time.RFC3339)))
					break
				}
				if ev.At < headAt {
					reject("time runs backwards in this feed")
					break
				}
				k, ok := keys[ev.KeyID]
				if !ok {
					reject("signed by unknown key " + ev.KeyID)
					break
				}
				if k.actor != ev.Actor {
					reject(fmt.Sprintf("key %s belongs to %s, not %s", ev.KeyID, k.actor, ev.Actor))
					break
				}
				if err := ev.check(k.pub); err != nil {
					reject(err.Error())
					break
				}
				if floor := now - pol.MaxBackdate.D().Milliseconds(); pol.MaxBackdate > 0 && ev.At < floor {
					ev.EffAt = floor
					rep.Clamped++
				}
				if err := insertEvent(w.tx, &ev); err != nil {
					reject(err.Error())
					break
				}
				accepted = append(accepted, ev)
				headSeq, headHash, headAt = ev.RSeq, ev.Hash, ev.At
			}
		}
		if len(accepted) == 0 {
			return nil
		}
		sort.Slice(accepted, func(i, j int) bool { return orderLess(accepted[i], accepted[j]) })
		var visible []Event
		for _, ev := range accepted {
			ok, err := trusted(w.tx, ev.KeyID)
			if err != nil {
				return err
			}
			if ok || ev.Type == evKeyRegistered {
				visible = append(visible, ev)
			} else {
				rep.Quarantined++
			}
		}
		// Events that arrive after later ones were projected only need a
		// full replay if applying them late could change the result.
		late := false
		for _, ev := range visible {
			if haveLast && orderLess(ev, last) && orderSensitive(ev) {
				late = true
				break
			}
		}
		if late {
			if err := rebuildViews(w.tx); err != nil {
				return err
			}
			rep.Rebuilt = true
		} else {
			for _, ev := range accepted {
				if err := apply(w.tx, ev); err != nil {
					return fmt.Errorf("apply %s: %w", ev.ID, err)
				}
			}
		}
		rep.Accepted = len(accepted)
		// The remote writer could not see our local dependents, so propagate
		// its invalidations here too. Propagation only touches active
		// records, so causes it already handled are no-ops.
		for _, ev := range visible {
			if root := propagationRoot(ev); root != "" {
				if err := w.propagate(root, "via "+ev.Replica+": "+ev.Type); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	rep.Flags = flagsFrom(emitted)
	return rep, nil
}

type keyInfo struct {
	pub   ed25519.PublicKey
	actor string
}

func (w *wtx) publicKeys() (map[string]keyInfo, error) {
	rows, err := w.tx.Query(`SELECT key_id, actor, public_key FROM keys`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]keyInfo{}
	for rows.Next() {
		var id, actor, pk string
		if err := rows.Scan(&id, &actor, &pk); err != nil {
			return nil, err
		}
		if pub, err := decodePublicKey(pk); err == nil {
			out[id] = keyInfo{pub: pub, actor: actor}
		}
	}
	return out, rows.Err()
}

func (w *wtx) head(replica string) (int64, string, int64, error) {
	var seq, at int64
	var hash string
	err := w.tx.QueryRow(`SELECT rseq, hash, at FROM events WHERE replica = ? ORDER BY rseq DESC LIMIT 1`, replica).Scan(&seq, &hash, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, genesisHash, 0, nil
	}
	return seq, hash, at, err
}

// propagationRoot returns the record whose change should invalidate its
// dependents, if ev is such a change.
func propagationRoot(ev Event) string {
	switch ev.Type {
	case evMemoryInvalidated, evMemoryRetracted, evAssumptionBroken, evDecisionReverted:
		var p statusChange
		_ = json.Unmarshal(ev.Payload, &p) // unreadable: no root, nothing to propagate
		return p.ID
	case evMemoryAsserted, evDecisionMade:
		var p struct {
			Supersedes string `json:"supersedes"`
		}
		_ = json.Unmarshal(ev.Payload, &p) // unreadable: nothing superseded
		return p.Supersedes
	}
	return ""
}

// Export writes events as JSON lines. With replica set, only that feed.
func (e *Engine) Export(w io.Writer, replica string) (int, error) {
	q, args := `ORDER BY replica, rseq`, []any{}
	if replica != "" {
		q, args = `WHERE replica = ? ORDER BY rseq`, []any{replica}
	}
	evs, err := e.loadEvents(q, args...)
	if err != nil {
		return 0, err
	}
	enc := json.NewEncoder(w)
	for _, ev := range evs {
		if err := enc.Encode(ev); err != nil {
			return 0, err
		}
	}
	return len(evs), nil
}

// ReadEvents parses JSON lines written by Export.
func ReadEvents(r io.Reader) ([]Event, error) {
	evs, torn, err := readEvents(r)
	if err == nil && torn {
		err = errors.New("last line is incomplete")
	}
	return evs, err
}

// readEvents parses JSON lines. An unterminated last line that doesn't parse
// is reported as torn rather than as an error: it is a write that was cut
// off, and the complete events before it are still good.
func readEvents(r io.Reader) (evs []Event, torn bool, err error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, false, err
	}
	lines := strings.Split(string(b), "\n")
	for i, l := range lines {
		if strings.TrimSpace(l) == "" {
			continue
		}
		var ev Event
		if err := json.Unmarshal([]byte(l), &ev); err != nil {
			if i == len(lines)-1 { // no trailing newline: cut off mid-write
				return evs, true, nil
			}
			return evs, false, fmt.Errorf("line %d: %w", i+1, err)
		}
		evs = append(evs, ev)
	}
	return evs, false, nil
}

// DirRemote is a sync remote that is just a directory: one append-only
// JSONL file per replica under feeds/. Each file has exactly one writer
// (its replica), so it works over a shared disk, Dropbox or a git repo.
// Readers verify everything; the directory itself is not trusted.
type DirRemote struct {
	Dir      string
	PullOnly bool // never push to it
}

func (r DirRemote) feedPath(replica string) string {
	return filepath.Join(r.Dir, "feeds", replica+".jsonl")
}

func (r DirRemote) readFeed(path string) ([]Event, bool, error) {
	f, err := os.Open(path) //nolint:gosec // a feed in the configured remote; its content is verified on import
	if os.IsNotExist(err) {
		return nil, false, nil
	} else if err != nil {
		return nil, false, err
	}
	defer f.Close() //nolint:errcheck // read-only
	return readEvents(f)
}

// repairTail truncates a torn last line left by an interrupted push. Only
// the feed's own replica writes to it, so this is safe.
func repairTail(path string) error {
	b, err := os.ReadFile(path) //nolint:gosec // our own feed in the configured remote
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || len(b) == 0 || b[len(b)-1] == '\n' {
		return err
	}
	return os.Truncate(path, int64(strings.LastIndexByte(string(b), '\n')+1))
}

// Push appends this replica's new events to its feed in the remote.
func (e *Engine) Push(r DirRemote) (int, error) {
	if err := repairTail(r.feedPath(e.replica)); err != nil {
		return 0, err
	}
	remote, _, err := r.readFeed(r.feedPath(e.replica))
	if err != nil {
		return 0, err
	}
	n := int64(len(remote))
	if n > 0 {
		var have string
		err := e.db.QueryRow(`SELECT hash FROM events WHERE replica = ? AND rseq = ?`, e.replica, n).Scan(&have)
		if err != nil || have != remote[n-1].Hash || remote[n-1].RSeq != n {
			return 0, fmt.Errorf("remote feed for %s does not match the local log; refusing to push", e.replica)
		}
	}
	evs, err := e.loadEvents(`WHERE replica = ? AND rseq > ? ORDER BY rseq`, e.replica, n)
	if err != nil || len(evs) == 0 {
		return 0, err
	}
	if err := os.MkdirAll(filepath.Dir(r.feedPath(e.replica)), 0o755); err != nil { //nolint:gosec // a shared remote; peers must read it
		return 0, err
	}
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	for _, ev := range evs {
		if err := enc.Encode(ev); err != nil {
			return 0, err
		}
	}
	f, err := os.OpenFile(r.feedPath(e.replica), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644) //nolint:gosec // as above
	if err != nil {
		return 0, err
	}
	// One write, then sync: a reader sees whole lines or a torn tail, which
	// it skips and the next push repairs.
	if _, err := f.WriteString(buf.String()); err != nil {
		_ = f.Close() // the write error is the one to report
		return 0, err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close() // as above
		return 0, err
	}
	return len(evs), f.Close()
}

// Pull imports every other replica's feed from the remote.
func (e *Engine) Pull(r DirRemote) (*ImportReport, error) {
	paths, err := filepath.Glob(filepath.Join(r.Dir, "feeds", "*.jsonl"))
	if err != nil {
		return nil, err
	}
	var all []Event
	var problems []string
	for _, p := range paths {
		if strings.TrimSuffix(filepath.Base(p), ".jsonl") == e.replica {
			continue
		}
		// A bad feed is reported, not fatal: one broken peer must not stop
		// sync with the others. Events before the bad line still import.
		evs, _, err := r.readFeed(p)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", filepath.Base(p), err))
		}
		all = append(all, evs...)
	}
	rep, err := e.Import(all)
	if rep != nil {
		rep.Rejected = append(rep.Rejected, problems...)
	}
	return rep, err
}

// Sync pulls, then pushes, so that suspect flags raised locally by the pull
// reach the remote in the same round. A pull-only remote is never written.
func (e *Engine) Sync(r DirRemote) (*ImportReport, int, error) {
	rep, err := e.Pull(r)
	if err != nil || r.PullOnly {
		return rep, 0, err
	}
	n, err := e.Push(r)
	return rep, n, err
}

// AddRemote saves a named directory remote. Remotes are local config. A
// pull-only remote is a read-only source, such as a team's shared memory
// that a curator publishes.
func (e *Engine) AddRemote(name, dir string, pullOnly bool) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	if !pullOnly {
		if err := os.MkdirAll(filepath.Join(abs, "feeds"), 0o755); err != nil { //nolint:gosec // a shared remote
			return err
		}
	}
	v := abs
	if pullOnly {
		v = "pull-only:" + abs
	}
	return e.setMeta("remote."+name, v)
}

// Remotes lists configured remotes by name.
func (e *Engine) Remotes() (map[string]DirRemote, error) {
	rows, err := e.db.Query(`SELECT key, value FROM meta WHERE key LIKE 'remote.%'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]DirRemote{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		dir, pullOnly := strings.CutPrefix(v, "pull-only:")
		out[strings.TrimPrefix(k, "remote.")] = DirRemote{Dir: dir, PullOnly: pullOnly}
	}
	return out, rows.Err()
}
