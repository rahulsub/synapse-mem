package smem

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestReadCostVsActions measures what a fresh process pays to read a store as
// its action history grows while the memories stay fixed. It is slow, so it
// only runs with SMEM_BENCH=1:
//
//	make build
//	SMEM_BENCH=1 SMEM_BENCH_BIN=$PWD/bin/smem go test ./smem -run TestReadCostVsActions -count=1 -v
//
// SMEM_BENCH_SIZES overrides the action counts (comma separated, the first is
// the baseline for ratios). SMEM_BENCH_RAW names a CSV file for every sample.
// SMEM_BENCH_BIN adds a mode that execs the built binary for each sample.
func TestReadCostVsActions(t *testing.T) {
	if os.Getenv("SMEM_BENCH") == "" {
		t.Skip("set SMEM_BENCH=1")
	}
	sizes := []int{0, 1000, 10000}
	if s := os.Getenv("SMEM_BENCH_SIZES"); s != "" {
		sizes = nil
		for _, f := range splitComma(s) {
			n, err := strconv.Atoi(strings.TrimSpace(f))
			if err != nil {
				t.Fatalf("SMEM_BENCH_SIZES: %v", err)
			}
			sizes = append(sizes, n)
		}
	}

	var raw *csv.Writer
	if p := os.Getenv("SMEM_BENCH_RAW"); p != "" {
		f, err := os.Create(p)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		raw = csv.NewWriter(f)
		defer raw.Flush()
		_ = raw.Write([]string{"mode", "actions", "op", "sample", "ns"})
	}

	fmt.Printf("read cost vs actions: %s %s/%s, %d CPUs, %s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), time.Now().Format(time.RFC3339))
	fmt.Printf("page cache warm; 3 discarded + %d samples per cell; no -race expected\n", benchSamples)

	feed := benchFeed(t)
	stores := make([]*benchStore, len(sizes))
	for i, n := range sizes {
		t0 := time.Now()
		stores[i] = buildBenchStore(t, n, feed)
		fmt.Printf("fixture n=%-6d built in %v: %d events, %d memories, gaps %d\n", n, time.Since(t0).Round(time.Millisecond),
			stores[i].events(t), benchMemories, n/500)
	}

	engine := benchCells(stores, engineOps)
	runBenchCells(t, "engine", engine, raw, func(s *benchStore, op benchOp) error { return s.sampleEngine(op) },
		func(s *benchStore) { s.warmEngine(t) }, false)

	if bin := os.Getenv("SMEM_BENCH_BIN"); bin != "" {
		proc := benchCells(stores, processOps)
		runBenchCells(t, "process", proc, raw, func(s *benchStore, op benchOp) error { return s.sampleProcess(bin, op) },
			func(s *benchStore) { s.warmProcess(t, bin) }, true)
	}
}

const (
	benchSamples  = 30
	benchDiscard  = 3
	benchMemories = 100
	benchFeedSize = 50
	benchActor    = "bench"
	benchSession  = "s-bench"
)

type benchOp struct {
	name string
	// args is the CLI command for process mode.
	args []string
	run  func(e *Engine, now int64) error
}

var engineOps = []benchOp{
	{name: "recall", run: func(e *Engine, _ int64) error {
		_, err := e.Recall(RecallQuery{Text: "deploy cache", NoRecord: true})
		return err
	}},
	{name: "context", run: func(e *Engine, _ int64) error { _, err := e.Context(4000); return err }},
	{name: "review", run: func(e *Engine, _ int64) error { _, err := e.Review(); return err }},
	{name: "idleGaps", run: func(e *Engine, now int64) error { _, err := e.idleGaps(now); return err }},
	{name: "quarantined", run: func(e *Engine, _ int64) error { _, err := e.Quarantined(); return err }},
}

var processOps = []benchOp{
	{name: "recall", args: []string{"recall", "--no-record", "--json", "deploy", "cache"}},
	{name: "context", args: []string{"context", "--budget", "4000"}},
}

// benchStore is one fixture: fixed memories, a fixed untrusted feed and n actions.
type benchStore struct {
	n      int
	dir    string
	path   string
	keyDir string
	end    time.Time

	// The store as it was after warm-up, to prove no sample wrote.
	count  int
	maxSeq int64
}

func (s *benchStore) open(now time.Time) (*Engine, error) {
	e, err := OpenWith(s.path, OpenOptions{})
	if err != nil {
		return nil, err
	}
	e.Now, e.Actor, e.Session, e.KeyDir = func() time.Time { return now }, benchActor, benchSession, s.keyDir
	return e, nil
}

func (s *benchStore) shape(t testing.TB) (count int, maxSeq int64) {
	t.Helper()
	e, err := s.open(s.end)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if err := e.db.QueryRow(`SELECT COUNT(*), MAX(seq) FROM events`).Scan(&count, &maxSeq); err != nil {
		t.Fatal(err)
	}
	return count, maxSeq
}

func (s *benchStore) events(t testing.TB) int { c, _ := s.shape(t); return c }

func (s *benchStore) freeze(t testing.TB) { s.count, s.maxSeq = s.shape(t) }

func (s *benchStore) assertFrozen(t testing.TB, mode string) {
	t.Helper()
	if c, m := s.shape(t); c != s.count || m != s.maxSeq {
		t.Fatalf("%s mode wrote to the n=%d store during sampling: %d events, max seq %d, was %d and %d", mode, s.n, c, m, s.count, s.maxSeq)
	}
}

// warmEngine writes the one session-context recall that later Context
// samples deduplicate against, then freezes the store.
func (s *benchStore) warmEngine(t testing.TB) {
	t.Helper()
	e, err := s.open(s.end)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Context(4000); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	s.freeze(t)
}

func (s *benchStore) sampleEngine(op benchOp) error {
	e, err := s.open(s.end)
	if err != nil {
		return err
	}
	err = op.run(e, ms(s.end))
	if cerr := e.Close(); err == nil {
		err = cerr
	}
	return err
}

func (s *benchStore) command(bin string, args ...string) *exec.Cmd {
	cmd := exec.Command(bin, append([]string{"--db", s.path}, args...)...)
	cmd.Dir = s.dir
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + s.dir,
		"SMEM_CONFIG=" + filepath.Join(s.dir, "no-config.json"),
		"SMEM_KEY_DIR=" + s.keyDir, "SMEM_ACTOR=" + benchActor, "SMEM_SESSION=" + benchSession,
	}
	return cmd
}

func (s *benchStore) sampleProcess(bin string, op benchOp) error {
	out, err := s.command(bin, op.args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", strings.Join(op.args, " "), err, out)
	}
	return nil
}

// warmProcess writes this store's one session-context recall at the real
// time the process clock reports, so later context samples deduplicate.
func (s *benchStore) warmProcess(t testing.TB, bin string) {
	t.Helper()
	if err := s.sampleProcess(bin, processOps[1]); err != nil {
		t.Fatal(err)
	}
	s.freeze(t)
}

// benchFeed is a fixed set of events from a second actor that no store trusts.
func benchFeed(t testing.TB) []Event {
	t.Helper()
	dir := t.TempDir()
	e, err := Open(filepath.Join(dir, "feed.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	e.Now = func() time.Time { return benchStart }
	e.Actor, e.Session, e.KeyDir = "feeder", "s-feeder", filepath.Join(dir, "keys")
	r := rand.New(rand.NewPCG(2, 2))
	for range benchFeedSize {
		if _, err := e.Remember(MemoryInput{Content: sentence(r)}); err != nil {
			t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	if _, err := e.Export(&buf, ""); err != nil {
		t.Fatal(err)
	}
	evs, err := ReadEvents(&buf)
	if err != nil {
		t.Fatal(err)
	}
	return evs
}

var benchStart = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

// buildBenchStore builds the fixture for n actions. The clock moves 10
// minutes per action and 30 hours every 500, so the active clock sees n/500
// real idle gaps.
func buildBenchStore(t testing.TB, n int, feed []Event) *benchStore {
	t.Helper()
	dir := t.TempDir()
	s := &benchStore{n: n, dir: dir, path: filepath.Join(dir, "smem.db"), keyDir: filepath.Join(dir, "keys"), end: benchStart}
	e, err := s.open(benchStart)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	now := benchStart
	e.Now = func() time.Time { return now }
	r := rand.New(rand.NewPCG(1, 1))
	for range benchMemories {
		if _, err := e.Remember(MemoryInput{Content: sentence(r)}); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := e.Import(feed)
	if err != nil || rep.Accepted != len(feed) {
		t.Fatalf("import feed: %+v %v", rep, err)
	}
	for i := 1; i <= n; i++ {
		now = now.Add(10 * time.Minute)
		if i%500 == 0 {
			now = now.Add(30 * time.Hour)
		}
		if _, err := e.RecordAction(ActionInput{Tool: "bench", Summary: "action " + strconv.Itoa(i)}); err != nil {
			t.Fatal(err)
		}
	}
	s.end = now
	if q, err := e.Quarantined(); err != nil || q == 0 {
		t.Fatalf("fixture needs quarantined events: %d %v", q, err)
	}
	return s
}

type benchCell struct {
	store *benchStore
	op    benchOp
}

type cellKey struct {
	n  int
	op string
}

func (c benchCell) key() cellKey { return cellKey{c.store.n, c.op.name} }

func benchCells(stores []*benchStore, ops []benchOp) []benchCell {
	var out []benchCell
	for _, s := range stores {
		for _, op := range ops {
			out = append(out, benchCell{s, op})
		}
	}
	return out
}

// runBenchCells samples every cell in shuffled rounds so drift spreads
// evenly. With block set, each store is measured contiguously instead and
// re-warmed if the block runs long (process mode uses the real clock).
func runBenchCells(t *testing.T, mode string, cells []benchCell, raw *csv.Writer,
	sample func(*benchStore, benchOp) error, warm func(*benchStore), block bool) {
	t.Helper()
	rng := rand.New(rand.NewPCG(7, 7))
	times := map[cellKey][]time.Duration{}
	var stores []*benchStore
	for _, c := range cells {
		if !slices.Contains(stores, c.store) {
			stores = append(stores, c.store)
		}
	}
	for _, s := range stores {
		warm(s)
	}
	runRounds := func(cs []benchCell, onSlow func()) {
		start := time.Now()
		for round := 0; round < benchDiscard+benchSamples; round++ {
			rng.Shuffle(len(cs), func(i, j int) { cs[i], cs[j] = cs[j], cs[i] })
			for _, c := range cs {
				if onSlow != nil && time.Since(start) > 8*time.Minute {
					onSlow()
					start = time.Now()
				}
				t0 := time.Now()
				if err := sample(c.store, c.op); err != nil {
					t.Fatal(err)
				}
				d := time.Since(t0)
				if round >= benchDiscard {
					times[c.key()] = append(times[c.key()], d)
					if raw != nil {
						_ = raw.Write([]string{mode, strconv.Itoa(c.store.n), c.op.name, strconv.Itoa(round - benchDiscard), strconv.FormatInt(d.Nanoseconds(), 10)})
					}
				}
			}
		}
	}
	if block {
		for _, s := range stores {
			// Warm again at the start of each block so every sample is
			// within the dedupe window of this store's own warm-up.
			warm(s)
			var mine []benchCell
			for _, c := range cells {
				if c.store == s {
					mine = append(mine, c)
				}
			}
			runRounds(mine, func() { warm(s) })
		}
	} else {
		runRounds(slices.Clone(cells), nil)
	}
	for _, s := range stores {
		s.assertFrozen(t, mode)
	}

	base := stores[0].n
	fmt.Printf("\n%s mode (ratio is the median against n=%d)\n", mode, base)
	fmt.Printf("%-12s %8s %10s %10s %10s %10s %8s\n", "op", "actions", "median", "p95", "min", "max", "ratio")
	seen := map[string]bool{}
	for _, c := range cells {
		if seen[c.op.name] {
			continue
		}
		seen[c.op.name] = true
		var baseMed time.Duration
		for _, s := range stores {
			ds := slices.Clone(times[cellKey{s.n, c.op.name}])
			slices.Sort(ds)
			med, p95 := ds[len(ds)/2], ds[min(len(ds)-1, len(ds)*95/100)]
			if s.n == base {
				baseMed = med
			}
			fmt.Printf("%-12s %8d %10s %10s %10s %10s %8.2f\n", c.op.name, s.n, round(med), round(p95), round(ds[0]), round(ds[len(ds)-1]),
				float64(med)/float64(baseMed))
		}
	}
}

func round(d time.Duration) time.Duration { return d.Round(10 * time.Microsecond) }
