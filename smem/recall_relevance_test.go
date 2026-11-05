package smem

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const defaultFloor = 0.345

var storeLines = func() []string {
	f, err := os.Open(filepath.Join("testdata", "recall_store.txt"))
	if err != nil {
		panic(err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			out = append(out, l)
		}
	}
	return out
}()

// Fixture lines (1-based) the acceptance queries are about.
const (
	lineKubeconfig = 61
	linePostgres   = 62
	lineCIRotation = 66
	lineDBCreds    = 67
	lineLogs       = 73
	lineMetrics    = 74
	lineTLS        = 76
	lineStagingOut = 92
	lineMostOut    = 96
	lineCafeteria  = 99
	lineEspresso   = 100
	lineOfficeFri  = 105
	lineParking    = 106
	lineDana       = 164
	lineZoe        = 181
)

type recallStore struct {
	e   *Engine
	c   *clock
	ids []string // by line, index 0 is line 1
}

// loadRecallStore loads one memory per fixture line a minute apart. With
// acme > 0, " for acme" is appended to the first acme lines other than the
// kubeconfig, cafeteria and espresso lines.
func loadRecallStore(t *testing.T, acme int) *recallStore {
	t.Helper()
	c := start()
	e := newEngine(t, "alice", c)
	s := &recallStore{e: e, c: c}
	for i, line := range storeLines {
		n := i + 1
		if acme > 0 && n != lineKubeconfig && n != lineCafeteria && n != lineEspresso {
			line = strings.TrimSuffix(line, ".") + " for acme."
			acme--
		}
		s.ids = append(s.ids, remember(t, e, "fact", line))
		c.advance(time.Minute)
	}
	c.advance(time.Hour)
	return s
}

func (s *recallStore) id(line int) string { return s.ids[line-1] }

func (s *recallStore) recall(t *testing.T, q string) []Scored {
	t.Helper()
	return must[[]Scored](t)(s.e.Recall(RecallQuery{Text: q, Limit: 100000, NoRecord: true}))
}

// relevance maps candidate ids to relevance; non-candidates are absent.
func (s *recallStore) relevance(t *testing.T, q string) map[string]float64 {
	t.Helper()
	out := map[string]float64{}
	for _, h := range s.recall(t, q) {
		out[h.ID] = h.Relevance
	}
	return out
}

func (s *recallStore) rankOf(hits []Scored, id string) int {
	for i, h := range hits {
		if h.ID == id {
			return i + 1
		}
	}
	return 0
}

func near(got, want, tol float64) bool { return math.Abs(got-want) <= tol }

func (s *recallStore) wantRel(t *testing.T, q string, line int, want float64) {
	t.Helper()
	got, ok := s.relevance(t, q)[s.id(line)]
	if !ok || !near(got, want, 0.001) {
		t.Errorf("%q line %d: relevance %.4f (candidate %v), want %.4f", q, line, got, ok, want)
	}
}

func TestAcceptanceKubeconfigRotation(t *testing.T) {
	s := loadRecallStore(t, 0)
	hits := s.recall(t, "rotate kubeconfig credentials")
	if r := s.rankOf(hits, s.id(lineKubeconfig)); r != 2 {
		t.Errorf("kubeconfig rank %d, want 2", r)
	}
	if r := s.rankOf(hits, s.id(lineCIRotation)); r != 1 {
		t.Errorf("CI rotation rank %d, want 1", r)
	}
	s.wantRel(t, "rotate kubeconfig credentials", lineKubeconfig, 0.3541)
	s.wantRel(t, "rotate kubeconfig credentials", lineCIRotation, 0.6459)
}

func TestAcceptanceCafeteriaWithoutStopwords(t *testing.T) {
	s := loadRecallStore(t, 0)
	hits := s.recall(t, "what is the cafeteria situation")
	if len(hits) != 1 || hits[0].ID != s.id(lineCafeteria) {
		t.Fatalf("want exactly the cafeteria memory, got %d hits", len(hits))
	}
	if !near(hits[0].Relevance, 0.4650, 0.001) {
		t.Errorf("relevance %.4f, want 0.4650", hits[0].Relevance)
	}
}

func TestAcceptancePostgresLag(t *testing.T) {
	s := loadRecallStore(t, 0)
	hits := s.recall(t, "postgres lag alert")
	if len(hits) == 0 || hits[0].ID != s.id(linePostgres) {
		t.Fatalf("postgres memory is not first: %v", ids(hits))
	}
	if !near(hits[0].Relevance, 0.7622, 0.001) {
		t.Errorf("relevance %.4f, want 0.7622", hits[0].Relevance)
	}
}

func TestAcceptanceEspressoBelowDefaultFloor(t *testing.T) {
	s := loadRecallStore(t, 0)
	got, ok := s.relevance(t, "staging database outages")[s.id(lineEspresso)]
	if !ok {
		t.Fatal("espresso is not a candidate (it matches outages)")
	}
	if !near(got, 0.3372, 0.001) || got >= defaultFloor {
		t.Errorf("espresso relevance %.4f, want 0.3372 and below %.3f", got, defaultFloor)
	}
}

func TestStemVariantsCountOnce(t *testing.T) {
	s := loadRecallStore(t, 0)
	a, _ := json.Marshal(s.recall(t, "staging database outages"))
	b, _ := json.Marshal(s.recall(t, "staging database outage outages"))
	if string(a) != string(b) {
		t.Error("a repeated stem variant changed the result")
	}
}

func TestLoneWeakMatchIsNotOne(t *testing.T) {
	s := loadRecallStore(t, 0)
	s.wantRel(t, "kubernetes rollout espresso", lineEspresso, 0.3029)
	s.wantRel(t, "postgres replica lag", linePostgres, 1)
	for _, q := range []string{"kubernetes rollout espresso", "staging database outages"} {
		for id, r := range s.relevance(t, q) {
			if r >= 1 {
				t.Errorf("%q: %s has relevance %.4f, want below 1", q, id, r)
			}
		}
	}
}

func TestSingleTermQueriesAreFullMatches(t *testing.T) {
	s := loadRecallStore(t, 0)
	seen := map[string]bool{}
	for _, line := range storeLines {
		for _, w := range wordRe.FindAllString(strings.ToLower(line), -1) {
			if seen[w] {
				continue
			}
			seen[w] = true
			hits := s.recall(t, w)
			if len(hits) == 0 {
				t.Errorf("single word %q found nothing", w)
				continue
			}
			for _, h := range hits {
				if h.Relevance != 1 {
					t.Errorf("single word %q: %s relevance %.6f, want exactly 1", w, h.ID, h.Relevance)
					break
				}
			}
		}
	}
	if len(seen) < 400 {
		t.Fatalf("only %d distinct words", len(seen))
	}
}

func TestOneMemoryStore(t *testing.T) {
	c := start()
	e := newEngine(t, "alice", c)
	id := remember(t, e, "fact", storeLines[lineEspresso-1])
	c.advance(time.Hour)
	for q, want := range map[string]float64{"staging database outages": 0, "espresso": 1} {
		hits := must[[]Scored](t)(e.Recall(RecallQuery{Text: q, NoRecord: true}))
		if len(hits) != 1 || hits[0].ID != id || hits[0].Relevance != want {
			t.Errorf("%q: %+v, want the memory at relevance %v", q, hits, want)
		}
	}
}

type calRow struct {
	label byte // P answers the prompt, N must not be injected, * is the best candidate of an unanswerable prompt
	query string
	line  int // 0 for * rows
	rel   float64
}

var calibration = []calRow{
	{'P', "rotate kubeconfig credentials", lineKubeconfig, 0.3541},
	{'P', "rotate kubeconfig credentials", lineCIRotation, 0.6459},
	{'P', "what is the cafeteria situation", lineCafeteria, 0.4650},
	{'P', "postgres lag alert", linePostgres, 0.7622},
	{'P', "hey can you remind me where the kubeconfig for staging is kept", lineKubeconfig, 0.3006},
	{'P', "where do we keep the kubeconfig", lineKubeconfig, 0.4650},
	{'P', "i need to rotate the kubeconfig credentials before the staging deploy", lineKubeconfig, 0.3291},
	{'P', "i need to rotate the kubeconfig credentials before the staging deploy", lineCIRotation, 0.5201},
	{'P', "i want to know what the cafeteria menu looks like this week", lineCafeteria, 0.3596},
	{'P', "does the cafeteria change its menu often", lineCafeteria, 0.6926},
	{'P', "is the postgres replica lag alert paging anyone right now", linePostgres, 0.5696},
	{'P', "who gets paged when postgres replication starts lagging", linePostgres, 0.6435},
	{'P', "who should i contact about the office espresso machine being broken", lineEspresso, 0.5699},
	{'P', "can you check whether staging database outages page the on-call team", lineStagingOut, 0.3200},
	{'P', "who leads the platform team", lineDana, 1.0},
	{'P', "how long do we keep application logs", lineLogs, 0.4421},
	{'P', "when do parking passes need renewing", lineParking, 0.8128},
	{'P', "where are the metrics dashboards", lineMetrics, 1.0},
	{'P', "how often are tls certificates renewed", lineTLS, 0.7058},
	{'P', "who can approve my production access request", lineZoe, 1.0},
	{'N', "staging database outages", lineEspresso, 0.3372},
	{'N', "staging database outage outages", lineEspresso, 0.3372},
	{'N', "kubernetes rollout espresso", lineEspresso, 0.3029},
	{'N', "kubernetes rollout espresso staging", lineEspresso, 0.2688},
	{'N', "kubernetes rollout espresso staging database", lineEspresso, 0.2357},
	{'N', "were there any staging database outages last night", lineEspresso, 0.1654},
	{'N', "were there any staging database outages last night", lineMostOut, 0.4806},
	{'N', "can you check whether staging database outages page the on-call team", lineEspresso, 0.0924},
	{'*', "can you help me figure out why the staging deploy keeps failing today", 0, 0.1613},
	{'*', "what time does the gym open on weekends", 0, 0.2149},
	{'*', "can i bring my dog to the office on fridays", 0, 0.3945},
	{'*', "how do i reset my laptop password", 0, 0.3029},
	{'*', "what is the dress code for client meetings", 0, 0.2123},
}

// documented lists the rows whose class disagrees with the default floor.
var documented = map[string]bool{
	"P hey can you remind me where the kubeconfig for staging is kept":           true,
	"P i need to rotate the kubeconfig credentials before the staging deploy/61": true,
	"P can you check whether staging database outages page the on-call team":     true,
	"N were there any staging database outages last night/96":                    true,
	"* can i bring my dog to the office on fridays":                              true,
}

func (r calRow) key() string {
	k := string(r.label) + " " + r.query
	if r.label == 'P' && r.query == "i need to rotate the kubeconfig credentials before the staging deploy" {
		k += fmt.Sprintf("/%d", r.line)
	}
	if r.label == 'N' && r.line == lineMostOut {
		k += fmt.Sprintf("/%d", r.line)
	}
	return k
}

func TestCalibrationTable(t *testing.T) {
	s := loadRecallStore(t, 0)
	var bad []string
	for _, r := range calibration {
		rel := s.relevance(t, r.query)
		var got float64
		if r.line > 0 {
			got = rel[s.id(r.line)]
		} else {
			for _, v := range rel {
				got = math.Max(got, v)
			}
		}
		if !near(got, r.rel, 0.001) {
			bad = append(bad, fmt.Sprintf("%-80s line %3d want %.4f got %.4f", r.query, r.line, r.rel, got))
			continue
		}
		above := got >= defaultFloor
		conflict := (r.label == 'P') != above
		if conflict != documented[r.key()] {
			bad = append(bad, fmt.Sprintf("%-80s line %3d %.4f class conflict %v, documented %v", r.query, r.line, got, conflict, documented[r.key()]))
		}
	}
	if len(bad) > 0 {
		t.Errorf("calibration mismatches:\n%s", strings.Join(bad, "\n"))
	}
}

func TestProjectNameStore(t *testing.T) {
	s := loadRecallStore(t, 95)
	s.wantRel(t, "kubernetes rollout espresso acme", lineEspresso, 0.2890)
	s.wantRel(t, "staging database outages acme", lineEspresso, 0.3033)
	s.wantRel(t, "rotate kubeconfig credentials acme", lineKubeconfig, 0.3353)
}

func TestProjectNameContinuity(t *testing.T) {
	const q = "kubernetes rollout espresso acme"
	ks := []int{0, 1, 2}
	for k := 94; k <= 101; k++ { // around the half-store point
		ks = append(ks, k)
	}
	var prevK int
	var prev float64
	for i, k := range ks {
		s := loadRecallStore(t, k)
		v := s.relevance(t, q)[s.id(lineEspresso)]
		if v > 0.3029+1e-12 {
			t.Errorf("k=%d: espresso %.6f exceeds its value without the project word", k, v)
		}
		if i > 0 && k == prevK+1 {
			step := math.Abs(v - prev)
			limit := 0.001
			if k <= 2 {
				limit = 0.01
			}
			if step > limit {
				t.Errorf("k %d to %d: step %.6f exceeds %.3f", prevK, k, step, limit)
			}
		}
		prevK, prev = k, v
	}
}

func TestLiveDocumentFrequencies(t *testing.T) {
	const q = "rotate kubeconfig credentials"
	s := loadRecallStore(t, 0)
	before := s.relevance(t, q)[s.id(lineKubeconfig)]
	if !near(before, 0.354143155355, 1e-9) {
		t.Fatalf("relevance %.12f, want 0.354143155355", before)
	}
	known := s.c.t
	cur := s.id(lineKubeconfig)
	for i := 0; i < 4; i++ {
		s.c.advance(time.Minute)
		var err error
		cur, _, err = s.e.Supersede(cur, MemoryInput{Kind: "fact", Content: storeLines[lineKubeconfig-1]})
		ok(t, err)
	}
	if got := s.relevance(t, q)[cur]; !near(got, before, 1e-9) {
		t.Errorf("after four supersedes: %.12f, want %.12f", got, before)
	}
	old := must[[]Scored](t)(s.e.Recall(RecallQuery{Text: q, KnownAt: known, Limit: 100000}))
	var seen bool
	for _, h := range old {
		if h.ID == s.id(lineKubeconfig) {
			seen = true
			if !near(h.Relevance, before, 1e-9) {
				t.Errorf("KnownAt before the supersedes: %.12f, want %.12f", h.Relevance, before)
			}
		}
	}
	if !seen {
		t.Error("KnownAt query lost the original version")
	}

	_, err := s.e.Retract(s.id(lineDBCreds), "test")
	ok(t, err)
	s.c.advance(time.Minute)
	if got := s.relevance(t, q)[cur]; !near(got, 0.3434, 0.001) {
		t.Errorf("after retracting a matching memory: %.4f, want 0.3434", got)
	}

	hits := must[[]Scored](t)(s.e.Recall(RecallQuery{Text: q, Kinds: []string{"fact"}, Limit: 100000, NoRecord: true}))
	for _, h := range hits {
		if h.ID == cur && !near(h.Relevance, s.relevance(t, q)[cur], 1e-12) {
			t.Error("a kind filter changed relevance")
		}
	}
}

func TestEmptyQueryKeepsRelevanceOne(t *testing.T) {
	s := loadRecallStore(t, 0)
	for _, q := range []string{"", "   ", "!!! ???"} {
		hits := s.recall(t, q)
		if len(hits) != len(storeLines) {
			t.Fatalf("%q: %d hits, want %d", q, len(hits), len(storeLines))
		}
		for _, h := range hits {
			if h.Relevance != 1 {
				t.Fatalf("%q: relevance %v, want 1", q, h.Relevance)
			}
		}
	}
	if out := must[string](t)(s.e.Context(0)); !strings.Contains(out, "\n- [mem-") {
		t.Errorf("session context lost the memories: %.200s", out)
	}
}

func TestRecallIsDeterministic(t *testing.T) {
	s := loadRecallStore(t, 0)
	queries := []string{"what is the cafeteria situation", "kubernetes rollout espresso"}
	for _, r := range calibration {
		queries = append(queries, r.query)
	}
	for _, q := range queries {
		a, err := json.Marshal(s.recall(t, q))
		ok(t, err)
		b, err := json.Marshal(s.recall(t, q))
		ok(t, err)
		if string(a) != string(b) {
			t.Errorf("%q: two runs differ", q)
		}
	}
}

func TestRebuildKeepsRelevance(t *testing.T) {
	s := loadRecallStore(t, 0)
	before, _ := json.Marshal(s.recall(t, "rotate kubeconfig credentials"))
	ok(t, s.e.Rebuild())
	after, _ := json.Marshal(s.recall(t, "rotate kubeconfig credentials"))
	if string(before) != string(after) {
		t.Error("recall changed across Rebuild")
	}
}

func TestManyCandidates(t *testing.T) {
	c := start()
	e := newEngine(t, "alice", c)
	const n = 1100
	for i := 0; i < n; i++ {
		remember(t, e, "fact", fmt.Sprintf("alpha service note number %d", i))
	}
	c.advance(time.Hour)
	hits := must[[]Scored](t)(e.Recall(RecallQuery{Text: "alpha", Limit: 5000, NoRecord: true}))
	if len(hits) != n {
		t.Errorf("%d hits, want %d", len(hits), n)
	}
}

// appendingAWordNeverRaises checks the monotonicity property: adding a word
// to a query never raises the relevance of a memory the word does not match.
func appendingAWordNeverRaises(t *testing.T, s *recallStore, queries, words []string) {
	t.Helper()
	matches := map[string]map[string]bool{}
	matched := func(w string) map[string]bool {
		if m, ok := matches[w]; ok {
			return m
		}
		m := map[string]bool{}
		rows, err := s.e.db.Query(`SELECT id FROM memories_fts WHERE memories_fts MATCH ?`, `"`+w+`"*`)
		ok(t, err)
		defer rows.Close()
		for rows.Next() {
			var id string
			ok(t, rows.Scan(&id))
			m[id] = true
		}
		ok(t, rows.Err())
		matches[w] = m
		return m
	}
	checks, bad := 0, 0
	for _, q := range queries {
		base := s.relevance(t, q)
		for _, w := range words {
			ext := s.relevance(t, q+" "+w)
			hit := matched(w)
			for id, r := range base {
				checks++
				if !hit[id] && ext[id] > r+1e-12 {
					bad++
					if bad <= 5 {
						t.Errorf("%q + %q: %s rose from %.6f to %.6f", q, w, id, r, ext[id])
					}
				}
			}
		}
	}
	if bad > 0 {
		t.Errorf("%d of %d checks violated monotonicity", bad, checks)
	}
	t.Logf("%d checks", checks)
}

func monotonicityInputs() (queries, words []string) {
	// Every calibration prompt runs with SMEM_FULL_SWEEP=1; by default the
	// acceptance prompts, one prompt per edge shape and the prefix pairs do.
	if os.Getenv("SMEM_FULL_SWEEP") != "" {
		seenQuery := map[string]bool{}
		for _, r := range calibration {
			if !seenQuery[r.query] {
				seenQuery[r.query] = true
				queries = append(queries, r.query)
			}
		}
	} else {
		queries = []string{
			"rotate kubeconfig credentials", "what is the cafeteria situation", "postgres lag alert",
			"staging database outages", "kubernetes rollout espresso",
			"hey can you remind me where the kubeconfig for staging is kept",
			"what time does the gym open on weekends", "can i bring my dog to the office on fridays",
		}
	}
	queries = append(queries, "the", "who is it", "ci upgrade", "cilium upgrade", "config")
	seen := map[string]bool{}
	for _, line := range storeLines {
		for _, w := range wordRe.FindAllString(strings.ToLower(line), -1) {
			if !seen[w] {
				seen[w] = true
				words = append(words, w)
			}
		}
	}
	// A sample of the store vocabulary keeps the run short; the extras are
	// the edge words: project name, filler, prefixes, stopwords and non-ASCII.
	step := 30
	if os.Getenv("SMEM_FULL_SWEEP") != "" {
		step = 1
	}
	var sample []string
	for i, w := range words {
		if i%step == 0 {
			sample = append(sample, w)
		}
	}
	extras := strings.Fields("acme hey remind zzqx kubernetes ci cilium log logrotate config configuration outage the it café 東京 week weekends")
	return queries, append(sample, extras...)
}

func TestAppendingAWordNeverRaisesRelevance(t *testing.T) {
	queries, words := monotonicityInputs()
	t.Run("fixture", func(t *testing.T) { appendingAWordNeverRaises(t, loadRecallStore(t, 0), queries, words) })
	t.Run("project name store", func(t *testing.T) { appendingAWordNeverRaises(t, loadRecallStore(t, 95), queries, words) })
}
