package smem

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// activeEngine is an engine on the active decay clock.
func activeEngine(t *testing.T, actor string, c *clock, idle time.Duration) *Engine {
	t.Helper()
	e := newEngine(t, actor, c)
	e.Policy.Decay.Clock = "active"
	e.Policy.Decay.IdleAfter = Duration(idle)
	return e
}

// refIdleGaps is the idle-gap algorithm as it was before summaries: a full
// pass over this replica's events, with no cache.
func refIdleGaps(t *testing.T, e *Engine, now int64) [][2]int64 {
	t.Helper()
	idle := e.Policy.Decay.IdleAfter.D().Milliseconds()
	if e.Policy.Decay.Clock == "wall" || idle <= 0 {
		return nil
	}
	rows, err := e.db.Query(`SELECT at FROM events WHERE replica = ? AND rseq > 0 ORDER BY rseq`, e.replica)
	ats, err := queryAll(rows, err, func(s scanner) (int64, error) {
		var at int64
		return at, s.Scan(&at)
	})
	ok(t, err)
	if len(ats) == 0 {
		return nil
	}
	var gaps [][2]int64
	var prev int64
	for _, at := range ats {
		if prev != 0 && at-prev > idle {
			gaps = append(gaps, [2]int64{prev + idle, at})
		}
		prev = at
	}
	if now-prev > idle {
		gaps = append(gaps, [2]int64{prev + idle, now})
	}
	return gaps
}

// refQuarantined is the quarantine count as it was before summaries.
func refQuarantined(t *testing.T, e *Engine) int {
	t.Helper()
	var n int
	ok(t, e.db.QueryRow(`SELECT COUNT(*) FROM events ev WHERE ev.type != ? AND NOT EXISTS
		(SELECT 1 FROM key_trust t WHERE t.key_id = ev.key_id AND t.trusted = 1)`, evKeyRegistered).Scan(&n))
	return n
}

// refKeyCounts is the per-key event count as it was before summaries.
func refKeyCounts(t *testing.T, e *Engine) map[string]int {
	t.Helper()
	rows, err := e.db.Query(`SELECT k.key_id, (SELECT COUNT(*) FROM events ev WHERE ev.key_id = k.key_id) FROM keys k`)
	ok(t, err)
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var id string
		var n int
		ok(t, rows.Scan(&id, &n))
		out[id] = n
	}
	ok(t, rows.Err())
	return out
}

func sameGaps(a, b [][2]int64) bool {
	return slices.EqualFunc(a, b, func(x, y [2]int64) bool { return x == y })
}

func parityNows(t *testing.T, e *Engine) []int64 {
	t.Helper()
	var first, last int64
	ok(t, e.db.QueryRow(`SELECT MIN(at), MAX(at) FROM events`).Scan(&first, &last))
	idle := e.Policy.Decay.IdleAfter.D().Milliseconds()
	return []int64{first - 1, first + (last-first)/2, last, last + idle/2, last + 2*idle, last + 400*24*3600*1000}
}

// requireParity checks idle gaps, the quarantine count and per-key counts
// against the pre-summary algorithms, through e (with its in-process cache)
// and through a freshly opened engine (as a new CLI process would see them).
func requireParity(t *testing.T, e *Engine) {
	t.Helper()
	cold, err := e.Clone()
	ok(t, err)
	defer cold.Close()
	for name, x := range map[string]*Engine{"warm": e, "cold": cold} {
		for _, now := range parityNows(t, e) {
			got, err := x.idleGaps(now)
			ok(t, err)
			if want := refIdleGaps(t, e, now); !sameGaps(got, want) {
				t.Fatalf("%s idleGaps(%d):\n got %v\nwant %v", name, now, got, want)
			}
		}
		q, err := x.Quarantined()
		ok(t, err)
		if want := refQuarantined(t, e); q != want {
			t.Fatalf("%s Quarantined = %d, want %d", name, q, want)
		}
		keys, err := x.Keys()
		ok(t, err)
		want := refKeyCounts(t, e)
		if len(keys) != len(want) {
			t.Fatalf("%s Keys lists %d keys, want %d", name, len(keys), len(want))
		}
		for _, k := range keys {
			if k.Events != want[k.KeyID] {
				t.Fatalf("%s Keys: %s has %d events, want %d", name, k.KeyID, k.Events, want[k.KeyID])
			}
		}
	}
}

// syncFrom imports everything from one engine into another.
func syncFrom(t *testing.T, from, to *Engine) {
	t.Helper()
	var buf bytes.Buffer
	must[int](t)(from.Export(&buf, ""))
	evs := must[[]Event](t)(ReadEvents(&buf))
	must[*ImportReport](t)(to.Import(evs))
}

// rawEmit appends local events the way a writer from before summaries would:
// without refreshing them.
func rawEmit(t *testing.T, e *Engine, n int) {
	t.Helper()
	tx, err := e.db.Begin()
	ok(t, err)
	w := &wtx{e: e, tx: tx}
	for range n {
		p := actionPayload{ID: newID("act"), Tool: "raw"}
		if _, err := w.emit(evActionRecorded, p.ID, p); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
	}
	ok(t, tx.Commit())
}

// bulkActions records n actions in one transaction, step apart, with a
// 30 hour break every 500.
func bulkActions(t *testing.T, e *Engine, c *clock, n int, step time.Duration) {
	t.Helper()
	_, err := e.write(func(w *wtx) error {
		for i := 1; i <= n; i++ {
			c.advance(step)
			if i%500 == 0 {
				c.advance(30 * time.Hour)
			}
			p := actionPayload{ID: newID("act"), Tool: "bulk"}
			if _, err := w.emit(evActionRecorded, p.ID, p); err != nil {
				return err
			}
		}
		return nil
	})
	ok(t, err)
}

func dumpSummaries(t *testing.T, e *Engine) string {
	t.Helper()
	var b strings.Builder
	for _, q := range []string{
		`SELECT name, version, seq, replica, idle_ms, rseq, last_at FROM summary_state ORDER BY name`,
		`SELECT replica, idle_ms, ord, start_at, end_at FROM summary_idle_gaps ORDER BY replica, idle_ms, ord`,
		`SELECT key_id, events, regs FROM summary_key_events ORDER BY key_id`,
	} {
		rows, err := e.db.Query(q)
		ok(t, err)
		cols, _ := rows.Columns()
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			ok(t, rows.Scan(ptrs...))
			fmt.Fprintln(&b, vals...)
		}
		ok(t, rows.Err())
		rows.Close()
		b.WriteString("--\n")
	}
	return b.String()
}

func gapStateOf(t *testing.T, e *Engine, idleMs int64) (version, rseq int64, found bool) {
	t.Helper()
	err := e.db.QueryRow(`SELECT version, rseq FROM summary_state WHERE name = ?`, gapStateName(e.replica, idleMs)).Scan(&version, &rseq)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, false
	}
	ok(t, err)
	return version, rseq, true
}

func keyStateSeq(t *testing.T, e *Engine) int64 {
	t.Helper()
	var seq int64
	ok(t, e.db.QueryRow(`SELECT seq FROM summary_state WHERE name = 'key_events'`).Scan(&seq))
	return seq
}

func maxSeq(t *testing.T, e *Engine) (seq, rseq int64) {
	t.Helper()
	ok(t, e.db.QueryRow(`SELECT MAX(seq) FROM events`).Scan(&seq))
	ok(t, e.db.QueryRow(`SELECT MAX(rseq) FROM events WHERE replica = ?`, e.replica).Scan(&rseq))
	return seq, rseq
}

// injectFault makes the named refresh stages fail until the test ends.
func injectFault(t *testing.T, stages ...string) {
	t.Helper()
	summaryFault = func(stage string) error {
		if slices.Contains(stages, stage) {
			return errors.New("injected " + stage)
		}
		return nil
	}
	t.Cleanup(func() { summaryFault = nil })
}

func eventCount(t *testing.T, e *Engine) int {
	t.Helper()
	var n int
	ok(t, e.db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&n))
	return n
}

func TestSummariesMatchTheLogUnderRandomHistory(t *testing.T) {
	steps := []time.Duration{time.Minute, 30 * time.Minute, 59*time.Minute + 59*time.Second, time.Hour, 61 * time.Minute, 5 * time.Hour, 26 * time.Hour}
	for seed := uint64(1); seed <= 3; seed++ {
		t.Run(fmt.Sprint("seed", seed), func(t *testing.T) {
			r := rand.New(rand.NewPCG(seed, seed))
			c := start()
			a := activeEngine(t, "alice", c, time.Hour)
			peers := []*Engine{newEngine(t, "bob", c), newEngine(t, "carol", c)}
			for step := 0; step < 30; step++ {
				c.advance(steps[r.IntN(len(steps))])
				switch n := r.IntN(8); {
				case n < 3:
					remember(t, a, "fact", sentence(r))
				case n < 5:
					must[string](t)(a.RecordAction(ActionInput{Tool: "bash", Summary: sentence(r)}))
				case n < 7:
					p := peers[r.IntN(len(peers))]
					remember(t, p, "fact", sentence(r))
					syncFrom(t, p, a)
				default:
					var foreign []Key
					for _, k := range must[[]Key](t)(a.Keys()) {
						if k.Replica != a.replica {
							foreign = append(foreign, k)
						}
					}
					if len(foreign) > 0 {
						k := foreign[r.IntN(len(foreign))]
						ok(t, a.SetTrust(k.KeyID, !k.Trusted, "test"))
					}
				}
				requireParity(t, a)
			}
		})
	}
}

func TestSummariesStayExactWhenWritersSkipThem(t *testing.T) {
	c := start()
	a := activeEngine(t, "alice", c, time.Hour)
	b := newEngine(t, "bob", c)
	remember(t, a, "fact", "one")
	c.advance(5 * time.Hour)
	remember(t, a, "fact", "two")
	requireParity(t, a)

	// Local events from a writer that doesn't know about summaries.
	c.advance(3 * time.Hour)
	rawEmit(t, a, 3)
	// Imported events whose refresh fails behave the same way.
	remember(t, b, "fact", "from bob")
	injectFault(t, "key_events:written")
	syncFrom(t, b, a)
	summaryFault = nil
	requireParity(t, a)

	seq, rseq := maxSeq(t, a)
	if got := keyStateSeq(t, a); got >= seq {
		t.Fatalf("watermark %d should be behind the log (%d)", got, seq)
	}
	if _, got, _ := gapStateOf(t, a, time.Hour.Milliseconds()); got >= rseq {
		t.Fatalf("gap watermark %d should be behind the log (%d)", got, rseq)
	}

	c.advance(time.Minute)
	remember(t, a, "fact", "three")
	seq, rseq = maxSeq(t, a)
	if got := keyStateSeq(t, a); got != seq {
		t.Fatalf("watermark %d after one write, want %d", got, seq)
	}
	if _, got, _ := gapStateOf(t, a, time.Hour.Milliseconds()); got != rseq {
		t.Fatalf("gap watermark %d after one write, want %d", got, rseq)
	}
	requireParity(t, a)
}

func TestSummariesIgnoredWhenAbsentOrOutdated(t *testing.T) {
	idle := time.Hour
	build := func(t *testing.T) (*Engine, *clock) {
		c := start()
		e := activeEngine(t, "alice", c, idle)
		b := newEngine(t, "bob", c)
		for i := 0; i < 6; i++ {
			remember(t, e, "fact", fmt.Sprint("fact ", i))
			c.advance(3 * time.Hour)
		}
		remember(t, b, "fact", "from bob")
		syncFrom(t, b, e)
		requireParity(t, e)
		return e, c
	}
	t.Run("state rows deleted", func(t *testing.T) {
		e, _ := build(t)
		ok(t, execAll(e.db, `DELETE FROM summary_state`))
		requireParity(t, e)
	})
	t.Run("version mismatch with a bogus row", func(t *testing.T) {
		e, c := build(t)
		ok(t, execAll(e.db, `UPDATE summary_state SET version = 0`))
		ok(t, execAll(e.db, `INSERT INTO summary_idle_gaps (replica, idle_ms, ord, start_at, end_at) VALUES ('`+e.replica+`', `+fmt.Sprint(idle.Milliseconds())+`, 999, 1, 2)`))
		ok(t, execAll(e.db, `UPDATE summary_key_events SET events = events + 100`))
		requireParity(t, e)
		c.advance(time.Minute)
		remember(t, e, "fact", "repair")
		var n int
		ok(t, e.db.QueryRow(`SELECT COUNT(*) FROM summary_idle_gaps WHERE ord = 999`).Scan(&n))
		if n != 0 {
			t.Fatal("a write must delete the rows of a state it rebuilds")
		}
		requireParity(t, e)
	})
	t.Run("idle threshold changes", func(t *testing.T) {
		e, c := build(t)
		for _, d := range []time.Duration{2 * time.Hour, 30 * time.Minute, idle} {
			e.Policy.Decay.IdleAfter = Duration(d)
			requireParity(t, e)
			c.advance(time.Minute)
			remember(t, e, "fact", "after "+d.String())
			requireParity(t, e)
		}
	})
	t.Run("tables dropped under a running process", func(t *testing.T) {
		e, _ := build(t)
		ok(t, execAll(e.db, `DROP TABLE summary_idle_gaps; DROP TABLE summary_key_events; DROP TABLE summary_state`))
		e.gaps = gapCache{}
		now := parityNows(t, e)[3]
		got, err := e.idleGaps(now)
		ok(t, err)
		if !sameGaps(got, refIdleGaps(t, e, now)) {
			t.Fatal("idleGaps must fall back to the full computation")
		}
		if q, err := e.Quarantined(); err != nil || q != refQuarantined(t, e) {
			t.Fatalf("Quarantined %d %v", q, err)
		}
		keys, err := e.Keys()
		ok(t, err)
		want := refKeyCounts(t, e)
		for _, k := range keys {
			if k.Events != want[k.KeyID] {
				t.Fatalf("Keys fallback: %s has %d, want %d", k.KeyID, k.Events, want[k.KeyID])
			}
		}
	})
}

func execAll(db *sql.DB, q string) error {
	_, err := db.Exec(q)
	return err
}

func TestSummariesFollowAReplicaChange(t *testing.T) {
	dir := t.TempDir()
	c := start()
	idle := time.Hour
	open := func(path string) *Engine {
		e, err := Open(path)
		ok(t, err)
		t.Cleanup(func() { e.Close() })
		e.Now, e.Actor, e.Session, e.KeyDir = c.now, "alice", "s-alice", filepath.Join(dir, "keys")
		e.Policy.Decay.Clock, e.Policy.Decay.IdleAfter = "active", Duration(idle)
		return e
	}
	orig := open(filepath.Join(dir, "a.db"))
	for i := 0; i < 5; i++ {
		remember(t, orig, "fact", fmt.Sprint("fact ", i))
		c.advance(4 * time.Hour)
	}
	oldReplica := orig.replica
	var gapsBefore int
	ok(t, orig.db.QueryRow(`SELECT COUNT(*) FROM summary_idle_gaps WHERE replica = ?`, oldReplica).Scan(&gapsBefore))
	if gapsBefore == 0 {
		t.Fatal("the original store should have gaps")
	}
	ok(t, orig.Close())

	// A copy of the file is a new replica that continues the copied events.
	b, err := os.ReadFile(filepath.Join(dir, "a.db"))
	ok(t, err)
	ok(t, os.WriteFile(filepath.Join(dir, "copy.db"), b, 0o600))
	cp := open(filepath.Join(dir, "copy.db"))
	if cp.replica == oldReplica {
		t.Fatal("the copy should have started a new replica")
	}
	// Before any write the old replica's rows are unreachable.
	requireParity(t, cp)
	if got := must[[][2]int64](t)(cp.idleGaps(ms(c.now().Add(10 * idle)))); len(got) != 0 {
		t.Fatalf("the new replica has no events of its own yet, so no gaps; got %v", got)
	}

	// It then makes its own history, with its own gaps.
	for i := 0; i < 3; i++ {
		remember(t, cp, "fact", fmt.Sprint("copy ", i))
		c.advance(6 * time.Hour)
	}
	requireParity(t, cp)
	var stray int
	ok(t, cp.db.QueryRow(`SELECT COUNT(*) FROM summary_idle_gaps WHERE replica != ?`, cp.replica).Scan(&stray))
	if stray != 0 {
		t.Fatalf("%d gap rows of another replica survived a write", stray)
	}
	ok(t, cp.db.QueryRow(`SELECT COUNT(*) FROM summary_state WHERE name LIKE 'idle_gaps/%' AND replica != ?`, cp.replica).Scan(&stray))
	if stray != 0 {
		t.Fatalf("%d gap states of another replica survived a write", stray)
	}
}

func TestSummaryRefreshFailureNeverBlocksEvents(t *testing.T) {
	c := start()
	e := activeEngine(t, "alice", c, time.Hour)
	for i := 0; i < 4; i++ {
		remember(t, e, "fact", fmt.Sprint("fact ", i))
		c.advance(3 * time.Hour)
	}
	before := dumpSummaries(t, e)
	events := eventCount(t, e)

	// The refresh fails after both summaries wrote rows; the savepoint undoes them.
	injectFault(t, "idle_gaps:written")
	remember(t, e, "fact", "survives")
	if got := eventCount(t, e); got != events+1 {
		t.Fatalf("events %d -> %d: the event must commit", events, got)
	}
	if after := dumpSummaries(t, e); after != before {
		t.Fatalf("a failed refresh must leave the summaries as they were:\nbefore\n%s\nafter\n%s", before, after)
	}
	summaryFault = nil
	requireParity(t, e)

	// The next healthy write catches up.
	c.advance(time.Minute)
	remember(t, e, "fact", "heals")
	seq, rseq := maxSeq(t, e)
	if keyStateSeq(t, e) != seq {
		t.Fatal("key watermark should catch up")
	}
	if _, got, _ := gapStateOf(t, e, time.Hour.Milliseconds()); got != rseq {
		t.Fatal("gap watermark should catch up")
	}

	// If the savepoint itself can't be rolled back, the write fails visibly.
	events = eventCount(t, e)
	injectFault(t, "idle_gaps:written", "ROLLBACK TO summaries")
	if _, err := e.Remember(MemoryInput{Content: "lost"}); err == nil {
		t.Fatal("a write whose savepoint can't be rolled back must fail")
	}
	if got := eventCount(t, e); got != events {
		t.Fatalf("a failed write left %d new events", got-events)
	}
}

func TestRebuildReconstructsSummaries(t *testing.T) {
	c := start()
	e := activeEngine(t, "alice", c, time.Hour)
	b := newEngine(t, "bob", c)
	for i := 0; i < 5; i++ {
		remember(t, e, "fact", fmt.Sprint("fact ", i))
		c.advance(4 * time.Hour)
	}
	remember(t, b, "fact", "from bob")
	syncFrom(t, b, e)
	pristine := dumpSummaries(t, e)
	if problems := must[[]string](t)(e.checkSummaries()); len(problems) != 0 {
		t.Fatalf("a healthy store reports %v", problems)
	}

	ok(t, execAll(e.db, `UPDATE summary_key_events SET events = events + 7`))
	ok(t, execAll(e.db, `DELETE FROM summary_idle_gaps WHERE ord = 0`))
	ok(t, execAll(e.db, `INSERT INTO summary_idle_gaps (replica, idle_ms, ord, start_at, end_at) VALUES ('rep-gone', 1, 0, 1, 2)`))
	ok(t, execAll(e.db, `INSERT INTO summary_state (name, version, replica, idle_ms) VALUES ('idle_gaps/rep-gone/1', 1, 'rep-gone', 1)`))
	if problems := must[[]string](t)(e.checkSummaries()); len(problems) == 0 {
		t.Fatal("doctor's check should see corrupted summaries")
	}
	var warned bool
	for _, ch := range Doctor(context.Background(), e, nil, nil, false) {
		if ch.Name == "summaries" {
			warned = ch.Status == "warn"
		}
	}
	if !warned {
		t.Fatal("doctor should warn about the summaries")
	}

	// A failing refresh fails the rebuild instead of reporting success.
	injectFault(t, "key_events:written")
	if err := e.Rebuild(); err == nil {
		t.Fatal("rebuild must return a refresh error")
	}
	summaryFault = nil

	ok(t, e.Rebuild())
	if got := dumpSummaries(t, e); got != pristine {
		t.Fatalf("rebuild should reconstruct the summaries:\nwant\n%s\ngot\n%s", pristine, got)
	}
	if problems := must[[]string](t)(e.checkSummaries()); len(problems) != 0 {
		t.Fatalf("after rebuild: %v", problems)
	}
	for _, ch := range Doctor(context.Background(), e, nil, nil, false) {
		if ch.Name == "summaries" && ch.Status != "ok" {
			t.Fatalf("doctor after rebuild: %+v", ch)
		}
	}
	requireParity(t, e)
}

func TestSteadyStateReadsDoNotScanTheLog(t *testing.T) {
	c := start()
	e := activeEngine(t, "alice", c, 24*time.Hour)
	b := newEngine(t, "bob", c)
	remember(t, e, "fact", "deploy goes through staging")
	remember(t, b, "fact", "bob says deploy is easy")
	syncFrom(t, b, e)
	bulkActions(t, e, c, 600, 10*time.Minute)
	must[string](t)(e.Context(4000)) // writes the session-context recall that later calls deduplicate against

	reads := func(x *Engine) {
		t.Helper()
		must[[]Scored](t)(x.Recall(RecallQuery{Text: "deploy", NoRecord: true}))
		must[string](t)(x.Context(4000))
		must[*Review](t)(x.Review())
		must[int](t)(x.Quarantined())
		must[[]Key](t)(x.Keys())
	}
	fresh := must[*Engine](t)(e.Clone())
	defer fresh.Close()
	summaryRows.Store(0)
	reads(fresh)
	if n := summaryRows.Load(); n != 0 {
		t.Fatalf("steady-state reads scanned %d event rows", n)
	}
	requireParity(t, e)

	// Events a writer without summaries left behind cost exactly their number.
	c.advance(time.Minute)
	rawEmit(t, e, 5)
	fresh2 := must[*Engine](t)(e.Clone())
	defer fresh2.Close()
	summaryRows.Store(0)
	must[[]Scored](t)(fresh2.Recall(RecallQuery{Text: "deploy", NoRecord: true}))
	if n := summaryRows.Load(); n != 5 {
		t.Fatalf("5 unsummarized events should cost 5 rows, got %d", n)
	}
	requireParity(t, e)
}

func TestSummaryQueriesAreIndexBounded(t *testing.T) {
	c := start()
	e := activeEngine(t, "alice", c, time.Hour)
	b := newEngine(t, "bob", c)
	remember(t, e, "fact", "x")
	remember(t, b, "fact", "y")
	syncFrom(t, b, e)
	cases := []struct {
		name string
		sql  string
		args []any
		want []string
		deny []string
	}{
		{"gap delta", qGapDelta, []any{e.replica, 1, 2}, []string{"(replica=? AND rseq>? AND rseq<?)"}, []string{"TEMP B-TREE FOR ORDER BY"}},
		{"gap state", qGapState, []any{gapStateName(e.replica, 1), e.replica, 1}, []string{"PRIMARY KEY (name=?)", "PRIMARY KEY (replica=? AND idle_ms=?)"}, nil},
		{"key delta", qKeyDelta, []any{evKeyRegistered, 1}, []string{"INTEGER PRIMARY KEY (rowid>?)"}, nil},
		{"quarantined", qQuarantined, []any{evKeyRegistered}, []string{"INTEGER PRIMARY KEY (rowid>?)"}, nil},
		{"keys", qKeys, []any{summaryVersion}, []string{"INTEGER PRIMARY KEY (rowid>?)"}, nil},
	}
	scan := regexp.MustCompile(`^SCAN (TABLE )?(events|ev)\b`)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rows, err := e.db.Query(`EXPLAIN QUERY PLAN `+tc.sql, tc.args...)
			ok(t, err)
			defer rows.Close()
			var plan []string
			for rows.Next() {
				var id, parent, unused int
				var detail string
				ok(t, rows.Scan(&id, &parent, &unused, &detail))
				plan = append(plan, detail)
			}
			ok(t, rows.Err())
			all := strings.Join(plan, "\n")
			for _, d := range plan {
				if scan.MatchString(d) {
					t.Errorf("full scan of events: %q\n%s", d, all)
				}
			}
			for _, w := range tc.want {
				if !strings.Contains(all, w) {
					t.Errorf("plan lacks %q:\n%s", w, all)
				}
			}
			for _, d := range tc.deny {
				if strings.Contains(all, d) {
					t.Errorf("plan has %q:\n%s", d, all)
				}
			}
		})
	}
}

func TestSummariesLeaveVerifySyncAndWhyAlone(t *testing.T) {
	c := start()
	e := activeEngine(t, "alice", c, time.Hour)
	b := newEngine(t, "bob", c)
	m := remember(t, e, "fact", "deploys go through staging")
	d, _, err := e.Decide(DecisionInput{Question: "where to deploy", Choice: "staging", Rationale: "safer"})
	ok(t, err)
	c.advance(5 * time.Hour)
	act := must[string](t)(e.RecordAction(ActionInput{Tool: "bash", Summary: "deploy", Decision: d, Commit: "abc1234"}))
	remember(t, b, "fact", "from bob")
	syncFrom(t, b, e)

	snapshot := func() (string, string, string, string, []Head) {
		var buf bytes.Buffer
		must[int](t)(e.Export(&buf, ""))
		why := func(ref string) string {
			tr := must[*Trace](t)(e.Why(ref))
			out, err := json.Marshal(tr)
			ok(t, err)
			return string(out)
		}
		return buf.String(), why(act), why("abc1234"), why(m), must[[]Head](t)(e.Heads())
	}
	rep := must[*VerifyReport](t)(e.Verify())
	if !rep.OK {
		t.Fatalf("verify: %v", rep.Problems)
	}
	exp, wa, wc, wm, heads := snapshot()
	ok(t, e.Rebuild())
	exp2, wa2, wc2, wm2, heads2 := snapshot()
	if exp != exp2 || wa != wa2 || wc != wc2 || wm != wm2 || !slices.Equal(heads, heads2) {
		t.Fatal("rebuilding summaries changed an export, a why trace or the heads")
	}
	if rep := must[*VerifyReport](t)(e.Verify()); !rep.OK {
		t.Fatalf("verify after rebuild: %v", rep.Problems)
	}
	// Summaries are derived: dropping them changes nothing the log says.
	ok(t, execAll(e.db, `DELETE FROM summary_state; DELETE FROM summary_idle_gaps; DELETE FROM summary_key_events`))
	if exp3, _, _, _, _ := snapshot(); exp3 != exp {
		t.Fatal("export depends on summaries")
	}
}

func TestGapRebuildReadsOnlyLocalEvents(t *testing.T) {
	c := start()
	e := activeEngine(t, "alice", c, time.Hour)
	b := newEngine(t, "bob", c)
	bulkActions(t, b, c, 400, time.Minute)
	syncFrom(t, b, e)
	for i := 0; i < 10; i++ {
		c.advance(3 * time.Hour)
		remember(t, e, "fact", fmt.Sprint("local ", i))
	}
	ok(t, execAll(e.db, `DELETE FROM summary_state WHERE name LIKE 'idle_gaps/%'; DELETE FROM summary_idle_gaps`))
	var local int
	ok(t, e.db.QueryRow(`SELECT COUNT(*) FROM events WHERE replica = ?`, e.replica).Scan(&local))
	var all int
	ok(t, e.db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&all))
	if all < 400 {
		t.Fatalf("imported events should dominate: %d of %d are local", local, all)
	}

	summaryRows.Store(0)
	_, err := e.write(func(*wtx) error { return nil })
	ok(t, err)
	if n := summaryRows.Load(); int(n) != local {
		t.Fatalf("rebuilding the gap summary read %d rows, want the %d local events", n, local)
	}
	requireParity(t, e)
}

func TestLegacyLocalEventsOutOfTimeOrderStillSummarize(t *testing.T) {
	c := start()
	e := activeEngine(t, "alice", c, time.Hour)
	remember(t, e, "fact", "one")
	var maxAt, rseq int64
	ok(t, e.db.QueryRow(`SELECT MAX(at), MAX(rseq) FROM events WHERE replica = ?`, e.replica).Scan(&maxAt, &rseq))
	h := time.Hour.Milliseconds()
	// A log from before event times were forced to increase: the same
	// departure time starts two different gaps.
	tx, err := e.db.Begin()
	ok(t, err)
	for i, at := range []int64{maxAt + 5*h, maxAt + 10*h, maxAt + 5*h, maxAt + 20*h} {
		ev := Event{ID: newID("evt"), Replica: e.replica, RSeq: rseq + int64(i) + 1, At: at, Actor: "alice", KeyID: "key-legacy",
			Type: evActionRecorded, Subject: "act-legacy", Payload: json.RawMessage(`{}`), Prev: "x", Hash: "x", Sig: "x"}
		ok(t, insertEvent(tx, &ev))
	}
	ok(t, tx.Commit())
	c.advance(time.Minute)
	remember(t, e, "fact", "after")
	if _, got, _ := gapStateOf(t, e, h); got != rseq+5 {
		t.Fatalf("refresh should keep up with legacy events: watermark %d", got)
	}
	requireParity(t, e)
}

func TestKeepsAtMostThreeIdleStates(t *testing.T) {
	c := start()
	e := activeEngine(t, "alice", c, time.Hour)
	for i := 0; i < 6; i++ {
		remember(t, e, "fact", fmt.Sprint("fact ", i))
		c.advance(9 * time.Hour)
	}
	for _, d := range []time.Duration{time.Hour, 2 * time.Hour, 3 * time.Hour, 4 * time.Hour, 5 * time.Hour} {
		e.Policy.Decay.IdleAfter = Duration(d)
		c.advance(time.Minute)
		remember(t, e, "fact", "with "+d.String())
		var states int
		ok(t, e.db.QueryRow(`SELECT COUNT(*) FROM summary_state WHERE name LIKE 'idle_gaps/%'`).Scan(&states))
		if states > 3 {
			t.Fatalf("%d idle states after %v", states, d)
		}
		if _, _, found := gapStateOf(t, e, d.Milliseconds()); !found {
			t.Fatalf("the current threshold %v lost its state", d)
		}
		var orphans int
		ok(t, e.db.QueryRow(`SELECT COUNT(*) FROM (SELECT DISTINCT replica, idle_ms FROM summary_idle_gaps) g
			WHERE NOT EXISTS (SELECT 1 FROM summary_state s WHERE s.replica = g.replica AND s.idle_ms = g.idle_ms)`).Scan(&orphans))
		if orphans != 0 {
			t.Fatalf("%d gap sets without a state", orphans)
		}
		requireParity(t, e)
	}
}

func TestAsOfAndKnownAtUnchangedBySummaries(t *testing.T) {
	c := start()
	e := activeEngine(t, "alice", c, time.Hour)
	t0 := c.now()
	m1 := remember(t, e, "fact", "the cache ttl is 60s")
	c.advance(5 * time.Hour)
	m2 := remember(t, e, "fact", "the cache is redis")
	must[[]Scored](t)(e.Recall(RecallQuery{Text: "cache"}))
	c.advance(30 * time.Minute)
	ok(t, e.Reconfirm(m1, 0, "checked"))
	c.advance(8 * time.Hour)
	must[[]Scored](t)(e.Recall(RecallQuery{Text: "cache ttl"}))
	c.advance(2 * time.Hour)
	_ = m2

	type probe struct{ asOf, known time.Time }
	probes := []probe{{}, {asOf: t0.Add(time.Hour)}, {known: t0.Add(6 * time.Hour)}, {asOf: t0.Add(6 * time.Hour), known: t0.Add(14 * time.Hour)}}
	run := func(x *Engine) [][]Scored {
		var out [][]Scored
		for _, p := range probes {
			out = append(out, must[[]Scored](t)(x.Recall(RecallQuery{Text: "cache", AsOf: p.asOf, KnownAt: p.known, NoRecord: true})))
		}
		return out
	}
	cold := must[*Engine](t)(e.Clone())
	withSummaries := run(cold)
	cold.Close()

	// With no persisted state every read falls back to the full pass.
	ok(t, execAll(e.db, `DELETE FROM summary_state; DELETE FROM summary_idle_gaps; DELETE FROM summary_key_events`))
	bare := must[*Engine](t)(e.Clone())
	defer bare.Close()
	without := run(bare)

	for i := range probes {
		if !slices.Equal(ids(withSummaries[i]), ids(without[i])) {
			t.Fatalf("probe %d: ids %v vs %v", i, ids(withSummaries[i]), ids(without[i]))
		}
		for j := range withSummaries[i] {
			if d := math.Abs(withSummaries[i][j].Score - without[i][j].Score); d > 1e-12 {
				t.Fatalf("probe %d hit %d: score differs by %g", i, j, d)
			}
		}
	}
}
