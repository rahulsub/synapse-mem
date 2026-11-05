package smem

import (
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// VerifyReport is the result of checking every event in the log.
type VerifyReport struct {
	OK       bool             `json:"ok"`
	Events   int              `json:"events"`
	Replicas map[string]int64 `json:"replicas"`
	Problems []string         `json:"problems"`
	Heads    []Head           `json:"heads"`
}

// Head is the latest event of one replica's feed. Publishing heads somewhere
// you can't edit later (a git commit, a chat message) makes rewriting the log
// detectable even by someone holding every key.
type Head struct {
	Replica string    `json:"replica"`
	RSeq    int64     `json:"rseq"`
	Hash    string    `json:"hash"`
	At      time.Time `json:"at"`
}

// Verify checks every event: each replica's chain is contiguous and
// correctly linked, each hash matches its content, and each signature is
// valid for the key that the actor registered.
func (e *Engine) Verify() (*VerifyReport, error) {
	evs, err := e.loadEvents(`ORDER BY replica, rseq`)
	if err != nil {
		return nil, err
	}
	rep := &VerifyReport{Replicas: map[string]int64{}}
	keys := map[string]ed25519.PublicKey{}
	actorOf := map[string]string{}
	for _, ev := range evs {
		if ev.Type != evKeyRegistered {
			continue
		}
		var p keyRegistered
		if json.Unmarshal(ev.Payload, &p) != nil {
			continue
		}
		if pub, err := decodePublicKey(p.PublicKey); err == nil && keyID(pub) == p.KeyID {
			keys[p.KeyID], actorOf[p.KeyID] = pub, p.Actor
		}
	}
	prev := map[string]string{}
	for _, ev := range evs {
		rep.Events++
		bad := func(format string, a ...any) {
			rep.Problems = append(rep.Problems, fmt.Sprintf("%s/%d (%s): ", ev.Replica, ev.RSeq, ev.Type)+fmt.Sprintf(format, a...))
		}
		want := rep.Replicas[ev.Replica] + 1
		if ev.RSeq != want {
			bad("expected rseq %d: events are missing", want)
		}
		if p, ok := prev[ev.Replica]; (ok && ev.Prev != p) || (!ok && ev.Prev != genesisHash) {
			bad("chain broken: prev does not match the preceding event's hash")
		}
		pub, ok := keys[ev.KeyID]
		switch {
		case !ok:
			bad("signed by unregistered key %s", ev.KeyID)
		case actorOf[ev.KeyID] != ev.Actor:
			bad("key %s belongs to %s, not %s", ev.KeyID, actorOf[ev.KeyID], ev.Actor)
		default:
			if err := ev.check(pub); err != nil {
				bad("%v", err)
			}
		}
		rep.Replicas[ev.Replica] = ev.RSeq
		prev[ev.Replica] = ev.Hash
	}
	rep.OK = len(rep.Problems) == 0
	rep.Heads, err = e.Heads()
	return rep, err
}

// Heads returns the latest event of each replica.
func (e *Engine) Heads() ([]Head, error) {
	return selectAll(e.db, func(s scanner) (Head, error) {
		var h Head
		var at int64
		err := s.Scan(&h.Replica, &h.RSeq, &h.Hash, &at)
		h.At = fromMs(at)
		return h, err
	}, `SELECT replica, rseq, hash, at FROM events ev
		WHERE rseq = (SELECT MAX(rseq) FROM events WHERE replica = ev.replica) ORDER BY replica`)
}

func (e *Engine) loadEvents(tail string, args ...any) ([]Event, error) {
	return selectAll(e.db, scanEvent, `SELECT `+eventCols+` FROM events `+tail, args...)
}

// Events lists events, newest first, optionally filtered.
func (e *Engine) Events(subject, typ string, limit int) ([]Event, error) {
	q, args := `WHERE 1 = 1`, []any{}
	if subject != "" {
		q += ` AND subject = ?`
		args = append(args, subject)
	}
	if typ != "" {
		q += ` AND type = ?`
		args = append(args, typ)
	}
	if limit <= 0 {
		limit = 50
	}
	return e.loadEvents(q+` ORDER BY at DESC, replica, rseq DESC LIMIT ?`, append(args, limit)...)
}

// Rebuild drops every projection and replays the log, then rebuilds the
// summaries from scratch. A summary that can't be rebuilt fails the rebuild.
func (e *Engine) Rebuild() error {
	_, err := e.write(func(w *wtx) error {
		if err := rebuildViews(w.tx); err != nil {
			return err
		}
		if err := resetSummaries(w.tx); err != nil {
			return err
		}
		return refreshSummaries(w.tx, e.replica, e.gapIdle())
	})
	return err
}

func rebuildViews(tx *sql.Tx) error {
	for _, t := range viewTables {
		if _, err := tx.Exec(`DROP TABLE IF EXISTS ` + t); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(viewsSchema + rulesSchema); err != nil {
		return err
	}
	evs, err := selectAll(tx, scanEvent, `SELECT `+eventCols+` FROM events ORDER BY at, replica, rseq`)
	if err != nil {
		return err
	}
	for _, ev := range evs {
		if err := apply(tx, ev); err != nil {
			return fmt.Errorf("replay %s: %w", ev.ID, err)
		}
	}
	return nil
}
