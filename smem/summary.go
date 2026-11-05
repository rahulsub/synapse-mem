package smem

import (
	"database/sql"
	"errors"
	"fmt"
	"sync/atomic"
)

// Summaries keep reads off the full event log: a watermark plus the totals up
// to it. A read adds only the events past the watermark and every write
// advances it, so a missing or stale summary costs time, never correctness.
// Key counts use events.seq; idle gaps use the local replica's rseq, whose
// delta is a range already in the order the algorithm needs.

// summaryVersion changes with the summary tables or the way they are built.
// A summary of another version is ignored and rebuilt by the next write.
const summaryVersion = 1

// maxGapStates is how many idle thresholds keep a gap summary, so processes
// with different decay.idle_after settings don't rebuild each other's.
const maxGapStates = 3

var (
	// summaryRows counts events read to bring a summary up to the log.
	summaryRows atomic.Int64
	// summaryFault lets tests fail a named step of a refresh.
	summaryFault func(stage string) error
)

func fault(stage string) error {
	if f := summaryFault; f != nil {
		return f(stage)
	}
	return nil
}

const (
	qGapState = `SELECT s.version, s.rseq, s.last_at, g.start_at, g.end_at
		FROM summary_state s
		LEFT JOIN summary_idle_gaps g ON g.replica = s.replica AND g.idle_ms = s.idle_ms
		WHERE s.name = ? AND s.replica = ? AND s.idle_ms = ?
		ORDER BY g.ord`

	qGapDelta = `SELECT at FROM events WHERE replica = ? AND rseq > ? AND rseq <= ? ORDER BY rseq`

	qKeyDelta = `SELECT key_id, COUNT(*), SUM(type = ?) FROM events WHERE seq > ? GROUP BY key_id`

	qQuarantined = `SELECT s.version,
		(SELECT COALESCE(SUM(c.events - c.regs), 0) FROM summary_key_events c
			WHERE NOT EXISTS (SELECT 1 FROM key_trust t WHERE t.key_id = c.key_id AND t.trusted = 1)),
		(SELECT COUNT(*) FROM events ev WHERE ev.seq > s.seq AND ev.type != ? AND NOT EXISTS
			(SELECT 1 FROM key_trust t WHERE t.key_id = ev.key_id AND t.trusted = 1))
		FROM summary_state s WHERE s.name = 'key_events'`

	qKeys = `WITH s AS (SELECT seq FROM summary_state WHERE name = 'key_events' AND version = ?),
		d AS (SELECT key_id, COUNT(*) AS n FROM events WHERE seq > (SELECT seq FROM s) GROUP BY key_id)
		SELECT k.key_id, k.actor, k.replica, COALESCE(t.trusted, 0),
			COALESCE(c.events, 0) + COALESCE(d.n, 0), (SELECT COUNT(*) FROM s)
		FROM keys k
		LEFT JOIN key_trust t ON t.key_id = k.key_id
		LEFT JOIN summary_key_events c ON c.key_id = k.key_id
		LEFT JOIN d ON d.key_id = k.key_id
		ORDER BY k.actor, k.key_id`
)

func gapStateName(replica string, idleMs int64) string {
	return fmt.Sprintf("idle_gaps/%s/%d", replica, idleMs)
}

// gapIdle is the idle threshold in ms, or 0 when the decay clock doesn't use gaps.
func (e *Engine) gapIdle() int64 {
	if e.Policy.Decay.Clock == "wall" {
		return 0
	}
	return max(e.Policy.Decay.IdleAfter.D().Milliseconds(), 0)
}

// refreshSafely advances the summaries inside the write transaction. A
// refresh that fails is undone and ignored: the events still commit, reads
// go through the log, and the next write retries. Only a failure of the
// savepoint itself fails the write.
func (e *Engine) refreshSafely(tx *sql.Tx) error {
	if err := savepoint(tx, "SAVEPOINT summaries"); err != nil {
		return err
	}
	if refreshSummaries(tx, e.replica, e.gapIdle()) != nil {
		if err := savepoint(tx, "ROLLBACK TO summaries"); err != nil {
			return err
		}
	}
	return savepoint(tx, "RELEASE summaries")
}

func savepoint(tx *sql.Tx, stmt string) error {
	if err := fault(stmt); err != nil {
		return err
	}
	_, err := tx.Exec(stmt)
	return err
}

// refreshSummaries brings every summary up to the end of the log.
func refreshSummaries(tx *sql.Tx, replica string, idleMs int64) error {
	if err := refreshKeyEvents(tx); err != nil {
		return err
	}
	if err := fault("key_events:written"); err != nil {
		return err
	}
	if idleMs > 0 {
		if err := refreshIdleGaps(tx, replica, idleMs); err != nil {
			return err
		}
	}
	if err := fault("idle_gaps:written"); err != nil {
		return err
	}
	return pruneGapStates(tx, replica, idleMs)
}

func refreshKeyEvents(tx *sql.Tx) error {
	var version, w, top int64
	err := tx.QueryRow(`SELECT version, seq FROM summary_state WHERE name = 'key_events'`).Scan(&version, &w)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err := tx.QueryRow(`SELECT COALESCE(MAX(seq), 0) FROM events`).Scan(&top); err != nil {
		return err
	}
	valid := err == nil && version == summaryVersion && w <= top
	if !valid {
		if _, err := tx.Exec(`DELETE FROM summary_key_events`); err != nil {
			return err
		}
		w = 0
	} else if w == top {
		return nil
	}
	type delta struct {
		key        string
		events, rg int64
	}
	rows, err := tx.Query(qKeyDelta, evKeyRegistered, w)
	ds, err := queryAll(rows, err, func(s scanner) (delta, error) {
		var d delta
		return d, s.Scan(&d.key, &d.events, &d.rg)
	})
	if err != nil {
		return err
	}
	for _, d := range ds {
		summaryRows.Add(d.events)
		if _, err := tx.Exec(`INSERT INTO summary_key_events (key_id, events, regs) VALUES (?, ?, ?)
			ON CONFLICT(key_id) DO UPDATE SET events = events + excluded.events, regs = regs + excluded.regs`,
			d.key, d.events, d.rg); err != nil {
			return err
		}
	}
	_, err = tx.Exec(`INSERT INTO summary_state (name, version, seq) VALUES ('key_events', ?, ?)
		ON CONFLICT(name) DO UPDATE SET version = excluded.version, seq = excluded.seq`, summaryVersion, top)
	return err
}

func refreshIdleGaps(tx *sql.Tx, replica string, idleMs int64) error {
	var head sql.NullInt64
	if err := tx.QueryRow(`SELECT MAX(rseq) FROM events WHERE replica = ?`, replica).Scan(&head); err != nil {
		return err
	}
	name := gapStateName(replica, idleMs)
	var version, rseq, lastAt, stIdle int64
	var stReplica string
	err := tx.QueryRow(`SELECT version, rseq, last_at, replica, idle_ms FROM summary_state WHERE name = ?`, name).
		Scan(&version, &rseq, &lastAt, &stReplica, &stIdle)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	valid := err == nil && version == summaryVersion && stReplica == replica && stIdle == idleMs &&
		head.Valid && rseq <= head.Int64
	if !valid {
		if _, err := tx.Exec(`DELETE FROM summary_idle_gaps WHERE replica = ? AND idle_ms = ?`, replica, idleMs); err != nil {
			return err
		}
		rseq, lastAt = 0, 0
		if !head.Valid {
			_, err := tx.Exec(`DELETE FROM summary_state WHERE name = ?`, name)
			return err
		}
	} else if rseq == head.Int64 {
		return nil
	}
	rows, err := tx.Query(qGapDelta, replica, rseq, head.Int64)
	ats, err := queryAll(rows, err, func(s scanner) (int64, error) {
		var at int64
		return at, s.Scan(&at)
	})
	if err != nil {
		return err
	}
	summaryRows.Add(int64(len(ats)))
	var ord int64
	if err := tx.QueryRow(`SELECT COUNT(*) FROM summary_idle_gaps WHERE replica = ? AND idle_ms = ?`, replica, idleMs).Scan(&ord); err != nil {
		return err
	}
	prev := lastAt
	for _, at := range ats {
		if prev != 0 && at-prev > idleMs {
			if _, err := tx.Exec(`INSERT INTO summary_idle_gaps (replica, idle_ms, ord, start_at, end_at) VALUES (?, ?, ?, ?, ?)`,
				replica, idleMs, ord, prev+idleMs, at); err != nil {
				return err
			}
			ord++
		}
		prev = at
	}
	_, err = tx.Exec(`INSERT INTO summary_state (name, version, replica, idle_ms, rseq, last_at) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET version = excluded.version, replica = excluded.replica, idle_ms = excluded.idle_ms,
			rseq = excluded.rseq, last_at = excluded.last_at`, name, summaryVersion, replica, idleMs, head.Int64, prev)
	return err
}

const gapStates = `substr(name, 1, 10) = 'idle_gaps/'`

// pruneGapStates drops the gap summaries nothing can read again: another
// replica's (a copied file continues as a new replica for good) and the
// oldest beyond maxGapStates.
func pruneGapStates(tx *sql.Tx, replica string, idleMs int64) error {
	if _, err := tx.Exec(`DELETE FROM summary_idle_gaps WHERE replica != ?`, replica); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM summary_state WHERE `+gapStates+` AND replica != ?`, replica); err != nil {
		return err
	}
	type st struct {
		name string
		idle int64
	}
	rows, err := tx.Query(`SELECT name, idle_ms FROM summary_state WHERE `+gapStates+` AND replica = ? ORDER BY rseq, name`, replica)
	states, err := queryAll(rows, err, func(s scanner) (st, error) {
		var x st
		return x, s.Scan(&x.name, &x.idle)
	})
	if err != nil {
		return err
	}
	left := len(states)
	for _, x := range states {
		if left <= maxGapStates {
			break
		}
		if x.idle == idleMs {
			continue
		}
		if _, err := tx.Exec(`DELETE FROM summary_idle_gaps WHERE replica = ? AND idle_ms = ?`, replica, x.idle); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM summary_state WHERE name = ?`, x.name); err != nil {
			return err
		}
		left--
	}
	return nil
}

// resetSummaries empties every summary.
func resetSummaries(tx *sql.Tx) error {
	_, err := tx.Exec(`DELETE FROM summary_idle_gaps; DELETE FROM summary_key_events; DELETE FROM summary_state`)
	return err
}

// gapBase is the idle-gap summary as persisted: closed gaps up to rseq.
type gapBase struct {
	rseq, lastAt int64
	gaps         [][2]int64
}

// loadGapBase reads this replica's persisted gap summary for idle in one
// statement. Anything unusable is an empty base, which is the full pass.
func (e *Engine) loadGapBase(idle int64) gapBase {
	rows, err := e.db.Query(qGapState, gapStateName(e.replica, idle), e.replica, idle)
	if err != nil {
		return gapBase{}
	}
	defer rows.Close()
	var b gapBase
	var seen bool
	for rows.Next() {
		var version int64
		var start, end sql.NullInt64
		if rows.Scan(&version, &b.rseq, &b.lastAt, &start, &end) != nil || version != summaryVersion {
			return gapBase{}
		}
		seen = true
		if start.Valid && end.Valid {
			b.gaps = append(b.gaps, [2]int64{start.Int64, end.Int64})
		}
	}
	if rows.Err() != nil || !seen {
		return gapBase{}
	}
	return b
}

// summarizedQuarantined counts events from untrusted keys through the key
// summary. ok is false when the summary can't be used.
func (e *Engine) summarizedQuarantined() (n int, ok bool) {
	var version, counted, tail int
	if err := e.db.QueryRow(qQuarantined, evKeyRegistered).Scan(&version, &counted, &tail); err != nil || version != summaryVersion {
		return 0, false
	}
	return counted + tail, true
}

// summarizedKeys lists keys with event counts through the key summary. ok is
// false when the summary can't be used.
func (e *Engine) summarizedKeys() (out []Key, ok bool) {
	rows, err := e.db.Query(qKeys, summaryVersion)
	if err != nil {
		return nil, false
	}
	defer rows.Close()
	for rows.Next() {
		var k Key
		var have int
		if rows.Scan(&k.KeyID, &k.Actor, &k.Replica, &k.Trusted, &k.Events, &have) != nil || have == 0 {
			return nil, false
		}
		out = append(out, k)
	}
	return out, rows.Err() == nil
}

// checkSummaries recomputes every summary from the log and reports where the
// stored one differs. A summary that is only behind isn't a problem: the next
// write catches it up. It reads the whole log, so it is for diagnostics.
func (e *Engine) checkSummaries() ([]string, error) {
	problems, err := e.checkKeyCounts()
	if err != nil {
		return nil, err
	}
	more, err := e.checkGapSets()
	return append(problems, more...), err
}

type keyCount struct{ events, regs int64 }

func (e *Engine) keyCounts(q string, args ...any) (map[string]keyCount, error) {
	rows, err := e.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]keyCount{}
	for rows.Next() {
		var k string
		var c keyCount
		if err := rows.Scan(&k, &c.events, &c.regs); err != nil {
			return nil, err
		}
		out[k] = c
	}
	return out, rows.Err()
}

func (e *Engine) checkKeyCounts() ([]string, error) {
	var version, w int64
	err := e.db.QueryRow(`SELECT version, seq FROM summary_state WHERE name = 'key_events'`).Scan(&version, &w)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && version != summaryVersion) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	want, err := e.keyCounts(`SELECT key_id, COUNT(*), SUM(type = ?) FROM events WHERE seq <= ? GROUP BY key_id`, evKeyRegistered, w)
	if err != nil {
		return nil, err
	}
	have, err := e.keyCounts(`SELECT key_id, events, regs FROM summary_key_events`)
	if err != nil {
		return nil, err
	}
	var problems []string
	if len(want) != len(have) {
		problems = append(problems, fmt.Sprintf("key counts cover %d keys, the log has %d", len(have), len(want)))
	}
	for k, c := range want {
		if have[k] != c {
			problems = append(problems, fmt.Sprintf("key %s is counted as %d events, the log has %d", k, have[k].events, c.events))
		}
	}
	return problems, nil
}

func (e *Engine) checkGapSets() ([]string, error) {
	type state struct {
		replica    string
		idle, rseq int64
	}
	rows, err := e.db.Query(`SELECT replica, idle_ms, rseq FROM summary_state WHERE `+gapStates+` AND version = ?`, summaryVersion)
	states, err := queryAll(rows, err, func(s scanner) (state, error) {
		var x state
		return x, s.Scan(&x.replica, &x.idle, &x.rseq)
	})
	if err != nil {
		return nil, err
	}
	var problems []string
	for _, s := range states {
		idle := s.idle
		rows, err := e.db.Query(`SELECT at FROM events WHERE replica = ? AND rseq <= ? ORDER BY rseq`, s.replica, s.rseq)
		ats, err := queryAll(rows, err, func(sc scanner) (int64, error) {
			var at int64
			return at, sc.Scan(&at)
		})
		if err != nil {
			return nil, err
		}
		var want [][2]int64
		var prev int64
		for _, at := range ats {
			if prev != 0 && at-prev > idle {
				want = append(want, [2]int64{prev + idle, at})
			}
			prev = at
		}
		rows, err = e.db.Query(`SELECT start_at, end_at FROM summary_idle_gaps WHERE replica = ? AND idle_ms = ? ORDER BY ord`, s.replica, idle)
		have, err := queryAll(rows, err, func(sc scanner) ([2]int64, error) {
			var g [2]int64
			return g, sc.Scan(&g[0], &g[1])
		})
		if err != nil {
			return nil, err
		}
		if fmt.Sprint(want) != fmt.Sprint(have) {
			problems = append(problems, fmt.Sprintf("idle gaps of %s at %d ms differ from the log", s.replica, idle))
		}
	}
	var orphans int
	if err := e.db.QueryRow(`SELECT COUNT(*) FROM (SELECT DISTINCT replica, idle_ms FROM summary_idle_gaps) g
		WHERE NOT EXISTS (SELECT 1 FROM summary_state s WHERE s.replica = g.replica AND s.idle_ms = g.idle_ms AND s.version = ?)`,
		summaryVersion).Scan(&orphans); err != nil {
		return nil, err
	}
	if orphans > 0 {
		problems = append(problems, fmt.Sprintf("%d idle gap set(s) belong to no summary", orphans))
	}
	return problems, nil
}
