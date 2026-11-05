package smem

import (
	"fmt"
	"testing"
	"time"
)

// These tests use SQL only: they describe the shape of the persisted
// summaries without naming anything in the implementation.

func TestSummariesFollowTheLog(t *testing.T) {
	c := start()
	e := newEngine(t, "alice", c)
	e.Policy.Decay.Clock = "active"
	e.Policy.Decay.IdleAfter = Duration(24 * time.Hour)
	remember(t, e, "fact", "auth uses JWT")
	c.advance(3 * 24 * time.Hour)
	must[string](t)(e.RecordAction(ActionInput{Tool: "bash", Summary: "deploy"}))
	c.advance(time.Hour)
	must[string](t)(e.RecordAction(ActionInput{Tool: "bash", Summary: "deploy again"}))

	var version, seq, maxSeq int64
	ok(t, e.db.QueryRow(`SELECT version, seq FROM summary_state WHERE name = 'key_events'`).Scan(&version, &seq))
	ok(t, e.db.QueryRow(`SELECT MAX(seq) FROM events`).Scan(&maxSeq))
	if version < 1 || seq != maxSeq {
		t.Fatalf("key_events state: version %d seq %d, log ends at %d", version, seq, maxSeq)
	}

	// Per-key counts equal what the log says.
	var diff int
	ok(t, e.db.QueryRow(`SELECT COUNT(*) FROM (
		SELECT key_id, COUNT(*) n, SUM(type = 'key.registered') r FROM events GROUP BY key_id
		EXCEPT SELECT key_id, events, regs FROM summary_key_events)`).Scan(&diff))
	if diff != 0 {
		t.Fatalf("%d key counts differ from the log", diff)
	}

	// One closed idle gap (the three days), recorded for this replica.
	idleMs := (24 * time.Hour).Milliseconds()
	name := fmt.Sprintf("idle_gaps/%s/%d", e.replica, idleMs)
	var rseq, head int64
	ok(t, e.db.QueryRow(`SELECT rseq FROM summary_state WHERE name = ?`, name).Scan(&rseq))
	ok(t, e.db.QueryRow(`SELECT MAX(rseq) FROM events WHERE replica = ?`, e.replica).Scan(&head))
	if rseq != head {
		t.Fatalf("gap state at rseq %d, log at %d", rseq, head)
	}
	var gaps int
	ok(t, e.db.QueryRow(`SELECT COUNT(*) FROM summary_idle_gaps WHERE replica = ? AND idle_ms = ?`, e.replica, idleMs).Scan(&gaps))
	if gaps != 1 {
		t.Fatalf("want one closed gap, have %d", gaps)
	}
}

func TestWallClockKeepsNoGapSummary(t *testing.T) {
	c := start()
	e := newEngine(t, "alice", c) // wall clock
	remember(t, e, "fact", "x")
	c.advance(72 * time.Hour)
	remember(t, e, "fact", "y")
	var n int
	ok(t, e.db.QueryRow(`SELECT COUNT(*) FROM summary_state WHERE name = 'key_events'`).Scan(&n))
	if n != 1 {
		t.Fatalf("key_events state rows: %d", n)
	}
	ok(t, e.db.QueryRow(`SELECT COUNT(*) FROM summary_state WHERE name LIKE 'idle_gaps/%'`).Scan(&n))
	if n != 0 {
		t.Fatalf("the wall clock has no use for gaps, yet %d states exist", n)
	}
}
