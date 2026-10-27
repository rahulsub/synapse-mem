package smem

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rahulsub/synapse-mem/judge"
)

// Check is one finding from Doctor.
type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"` // ok, warn or fail
	Detail string `json:"detail"`
}

// Doctor checks the setup around a store: config, identity, keys, judges,
// trust, spool and remotes. e may be nil when no store was found.
func Doctor(ctx context.Context, e *Engine, cfg *Config, cfgErr error, ping bool) []Check {
	var out []Check
	add := func(name, status, format string, a ...any) {
		out = append(out, Check{name, status, fmt.Sprintf(format, a...)})
	}
	if e == nil {
		add("store", "fail", "no .smem/smem.db here or in any parent directory, and SMEM_DB is not set; hooks do nothing until there is one (smem init)")
	} else {
		add("store", "ok", "%s (replica %s)", e.Path(), e.Replica())
	}
	switch {
	case cfgErr != nil:
		add("config", "fail", "%v", cfgErr)
	case cfg != nil && len(cfg.Sources) > 0:
		add("config", "ok", "%s", strings.Join(cfg.Sources, ", "))
	default:
		add("config", "ok", "defaults (no project or local config; local config would be %s)", cmp(LocalConfigPath(), "$SMEM_CONFIG"))
	}
	if e == nil {
		return out
	}

	switch {
	case os.Getenv("SMEM_ACTOR") != "":
		add("actor", "ok", "%s (SMEM_ACTOR)", e.Actor)
	case cfg != nil && cfg.Actor != "":
		add("actor", "ok", "%s (local config)", e.Actor)
	default:
		add("actor", "warn", "%s is a default (user@host); set SMEM_ACTOR or \"actor\" in the local config so an agent keeps one identity when its host name changes", e.Actor)
	}

	keyStatus, keyDetail := "ok", e.KeyDir
	if ephemeralPath(e.KeyDir) {
		keyStatus, keyDetail = "warn", e.KeyDir+" looks temporary; keys there are lost on restart (set SMEM_KEY_DIR or keys.dir)"
	}
	add("key dir", keyStatus, "%s", keyDetail)
	priv, err := loadKey(e.KeyDir, e.Actor)
	var registered string
	_ = e.db.QueryRow(`SELECT key_id FROM keys WHERE actor = ? AND replica = ? ORDER BY registered_at DESC LIMIT 1`,
		e.Actor, e.replica).Scan(&registered) // none registered yet is a normal answer
	switch {
	case err != nil:
		add("signing key", "fail", "%v", err)
	case priv == nil && registered != "":
		add("signing key", "fail", "%s signs this store with %s but its private key is missing from %s; writes will be refused until it is restored", e.Actor, registered, e.KeyDir)
	case priv == nil:
		add("signing key", "ok", "none yet for %s; one is created on first write", e.Actor)
	case registered != "" && keyID(priv.Public().(ed25519.PublicKey)) != registered:
		add("signing key", "warn", "%s has key %s on disk but signs this store with %s", e.Actor, keyID(priv.Public().(ed25519.PublicKey)), registered)
	default:
		add("signing key", "ok", "%s for %s", keyID(priv.Public().(ed25519.PublicKey)), e.Actor)
	}

	names := e.Judges.Names()
	if len(names) == 0 {
		add("judges", "warn", "none: fact-checks use checkers only (TYPESAFE_API_KEY or OPENROUTER_API_KEY for Jev; ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN for Claude)")
	} else {
		add("judges", "ok", "%s; acting needs %d agreeing check(s)", strings.Join(names, " → "), max(e.FactCheckPolicy.MinAgreeing, 1))
	}
	if ping {
		for _, r := range PingJudges(ctx, e.Judges) {
			if r.Err != "" {
				add("judge "+r.Judge, "fail", "%s", r.Err)
			} else {
				add("judge "+r.Judge, "ok", "%s answered in %d ms", r.Model, r.LatencyMs)
			}
		}
	}
	if health, err := e.JudgeHealth(24 * time.Hour); err == nil {
		for _, h := range health {
			switch {
			case h.Failed == 0:
				add("judge "+h.Judge, "ok", "%d call(s) in 24h, none failed", h.OK)
			case h.OK == 0:
				add("judge "+h.Judge, "fail", "all %d call(s) in 24h failed; last: %s", h.Failed, h.LastError)
			default:
				add("judge "+h.Judge, "warn", "%d of %d call(s) in 24h failed; last: %s", h.Failed, h.OK+h.Failed, h.LastError)
			}
		}
	}
	if len(e.FactCheckPolicy.withDefaults().Evidence.Allow) == 0 {
		add("evidence", "warn", "factcheck.evidence.allow is empty: no file evidence will be read")
	}
	add("checkers", "ok", "%d configured", len(e.Checkers))

	ks, _ := e.Keys()
	var untrusted []string
	for _, k := range ks {
		if !k.Trusted {
			untrusted = append(untrusted, fmt.Sprintf("%s (%s, %d events)", k.KeyID, k.Actor, k.Events))
		}
	}
	if n, _ := e.Quarantined(); n > 0 {
		add("trust", "warn", "%d event(s) quarantined from untrusted keys: %s. Trust with `smem keys trust <key-id>` or trust.keys in the local config", n, strings.Join(untrusted, ", "))
	} else {
		add("trust", "ok", "%d key(s), all trusted or with nothing quarantined", len(ks))
	}

	if n := e.SpoolBacklog(); n > 100 {
		add("spool", "warn", "%d tool calls waiting; nothing has written to the store for a while", n)
	} else {
		add("spool", "ok", "%d waiting", n)
	}

	rs, _ := e.Remotes()
	names = names[:0]
	for n := range rs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		r := rs[n]
		if _, err := os.Stat(filepath.Join(r.Dir, "feeds")); err != nil {
			add("remote "+n, "fail", "%s: %v", r.Dir, err)
		} else {
			add("remote "+n, "ok", "%s%s", r.Dir, map[bool]string{true: " (pull-only)"}[r.PullOnly])
		}
	}
	return out
}

// ephemeralPath reports whether dir is under a temporary directory.
func ephemeralPath(dir string) bool {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return false
	}
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		abs = real
	}
	for _, t := range []string{os.TempDir(), "/tmp", "/private/tmp", "/var/tmp", "/dev/shm", "/run/user"} {
		if real, err := filepath.EvalSymlinks(t); err == nil {
			t = real
		}
		if abs == t || strings.HasPrefix(abs, strings.TrimSuffix(t, "/")+"/") {
			return true
		}
	}
	return false
}

// PingResult is the outcome of asking one judge a trivial question.
type PingResult struct {
	Judge     string `json:"judge"`
	Model     string `json:"model,omitempty"`
	LatencyMs int64  `json:"latency_ms"`
	Err       string `json:"error,omitempty"`
}

// PingJudges asks every judge a tiny question, so a misconfigured judge
// shows up as an error instead of a silent fallback to the next one.
func PingJudges(ctx context.Context, c judge.Cascade) []PingResult {
	req := judge.Request{
		Purpose: "Connectivity check.",
		State:   map[string]any{"claim": "2 + 2 = 4", "evidence": "2 + 2 = 4"},
		Questions: []judge.Question{{ID: "relation", Kind: judge.Choice, Instructions: "Does the evidence support the claim?",
			Labels: []judge.Label{{Key: "supports", Description: "yes"}, {Key: "says_nothing", Description: "no"}}}},
	}
	var out []PingResult
	for _, st := range c.Stages {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		start := time.Now()
		r, err := st.Judge.Ask(ctx, req)
		cancel()
		p := PingResult{Judge: st.Judge.Name(), LatencyMs: time.Since(start).Milliseconds()}
		if err == nil {
			err = judge.Check(req, r)
		}
		if err != nil {
			p.Err = err.Error()
		} else {
			p.Model = r.Model
		}
		out = append(out, p)
	}
	return out
}

// Stats describes what a store holds.
type Stats struct {
	Events      int            `json:"events"`
	ByType      map[string]int `json:"by_type"`
	ByReplica   map[string]int `json:"by_replica"`
	Last24h     int            `json:"last_24h"`
	Last7d      int            `json:"last_7d"`
	Memories    map[string]int `json:"memories"` // by status
	Decisions   int            `json:"decisions"`
	Actions     int            `json:"actions"`
	Judgments   int            `json:"judgments"`
	Quarantined int            `json:"quarantined"`
	Spool       int            `json:"spool"`
	Bytes       int64          `json:"bytes"` // database plus WAL
}

// Stats counts what the store holds and how fast the log grows.
func (e *Engine) Stats() (*Stats, error) {
	s := &Stats{ByType: map[string]int{}, ByReplica: map[string]int{}, Memories: map[string]int{}}
	group := func(q string, into map[string]int, args ...any) error {
		rows, err := e.db.Query(q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var k string
			var n int
			if err := rows.Scan(&k, &n); err != nil {
				return err
			}
			into[k] = n
		}
		return rows.Err()
	}
	if err := group(`SELECT type, COUNT(*) FROM events GROUP BY type`, s.ByType); err != nil {
		return nil, err
	}
	if err := group(`SELECT replica, COUNT(*) FROM events GROUP BY replica`, s.ByReplica); err != nil {
		return nil, err
	}
	if err := group(`SELECT status, COUNT(*) FROM memories GROUP BY status`, s.Memories); err != nil {
		return nil, err
	}
	now := e.Now()
	for _, q := range []struct {
		dst  *int
		sql  string
		args []any
	}{
		{&s.Events, `SELECT COUNT(*) FROM events`, nil},
		{&s.Last24h, `SELECT COUNT(*) FROM events WHERE at > ?`, []any{ms(now.Add(-24 * time.Hour))}},
		{&s.Last7d, `SELECT COUNT(*) FROM events WHERE at > ?`, []any{ms(now.Add(-7 * 24 * time.Hour))}},
		{&s.Decisions, `SELECT COUNT(*) FROM decisions`, nil},
		{&s.Actions, `SELECT COUNT(*) FROM actions`, nil},
		{&s.Judgments, `SELECT COUNT(*) FROM judgments`, nil},
	} {
		if err := e.db.QueryRow(q.sql, q.args...).Scan(q.dst); err != nil {
			return nil, err
		}
	}
	var err error
	if s.Quarantined, err = e.Quarantined(); err != nil {
		return nil, err
	}
	s.Spool = e.SpoolBacklog()
	for _, suffix := range []string{"", "-wal"} {
		if fi, err := os.Stat(e.path + suffix); err == nil {
			s.Bytes += fi.Size()
		}
	}
	return s, nil
}
