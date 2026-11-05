package smem

import (
	"context"
	"fmt"
	"math"
	"slices"
	"strings"
	"testing"
)

func TestQueryWords(t *testing.T) {
	for _, tc := range []struct {
		text string
		want []string
	}{
		{"What is the CAFETERIA situation", []string{"cafeteria", "situation"}},
		{"cafeteria Cafeteria menu cafeteria", []string{"cafeteria", "menu"}},
		{"postgres, lag; alert!", []string{"postgres", "lag", "alert"}},
		{"the", []string{"the"}},
		{"who is it", []string{"who", "is", "it"}},
		{"the the is", []string{"the", "is"}},
		{"café 東京 v2", []string{"café", "東京", "v2"}},
		{"", nil},
		{"  !!! ??? ", nil},
	} {
		if got := queryWords(tc.text); !slices.Equal(got, tc.want) {
			t.Errorf("queryWords(%q) = %q, want %q", tc.text, got, tc.want)
		}
	}
}

func queryTokensOf(t *testing.T, e *Engine, words ...string) []string {
	t.Helper()
	ctx := context.Background()
	conn, err := e.db.Conn(ctx)
	ok(t, err)
	defer conn.Close()
	return must[[]string](t)(queryTokens(ctx, conn, words))
}

func queryRows(t *testing.T, e *Engine) int {
	t.Helper()
	conn, err := e.db.Conn(context.Background())
	ok(t, err)
	defer conn.Close()
	var n int
	ok(t, conn.QueryRowContext(context.Background(), `SELECT count(*) FROM temp.smem_query`).Scan(&n))
	return n
}

func TestQueryTokens(t *testing.T) {
	e := newEngine(t, "alice", start())
	for _, tc := range []struct {
		words []string
		want  []string
	}{
		{[]string{"staging", "database", "outage", "outages"}, []string{"stage", "databas", "outag"}},
		{[]string{"outage", "outages"}, []string{"outag"}},
		{[]string{"staging", "stage"}, []string{"stage"}},
		{[]string{"deploy", "deploys"}, []string{"deploi"}},
		{[]string{"café", "cafe"}, []string{"cafe"}},
		{[]string{"rotate", "kubeconfig", "credentials"}, []string{"rotat", "kubeconfig", "credenti"}},
	} {
		if got := queryTokensOf(t, e, tc.words...); !slices.Equal(got, tc.want) {
			t.Errorf("tokens of %q = %q, want %q", tc.words, got, tc.want)
		}
	}

	var many []string
	for i := 0; i < 100; i++ {
		many = append(many, fmt.Sprintf("w%d", i))
	}
	got := queryTokensOf(t, e, many...)
	if len(got) != maxQueryTerms || got[0] != "w0" || got[maxQueryTerms-1] != fmt.Sprintf("w%d", maxQueryTerms-1) {
		t.Errorf("cap: %d tokens, first %q last %q", len(got), got[0], got[len(got)-1])
	}
	if n := queryRows(t, e); n != 0 {
		t.Errorf("%d rows left after success", n)
	}

	ctx := context.Background()
	conn, err := e.db.Conn(ctx)
	ok(t, err)
	ok(t, conn.Close())
	if _, err := queryTokens(ctx, conn, []string{"x"}); err == nil {
		t.Error("a closed connection returned no error")
	}
	if n := queryRows(t, e); n != 0 {
		t.Errorf("%d rows left after an error", n)
	}
	if got := queryTokensOf(t, e, "staging"); !slices.Equal(got, []string{"stage"}) {
		t.Errorf("tokenizing after an error: %q", got)
	}
}

func TestTermWeight(t *testing.T) {
	for _, tc := range []struct{ n, df int }{{198, 0}, {198, 1}, {198, 21}, {198, 198}, {1, 0}, {1, 1}, {0, 0}} {
		if got, want := termWeight(tc.n, tc.df), math.Log(float64(tc.n+1)/float64(tc.df+1)); got != want {
			t.Errorf("termWeight(%d, %d) = %v, want %v", tc.n, tc.df, got, want)
		}
	}
	if got, want := termWeight(198, 0), math.Log(199); got != want {
		t.Errorf("absent term weighs %v, want ln(N+1) = %v", got, want)
	}
	for df := 0; df < 198; df++ {
		if termWeight(198, df+1) >= termWeight(198, df) {
			t.Fatalf("weight does not fall from df %d to %d", df, df+1)
		}
	}
	if termWeight(198, 198) != 0 {
		t.Error("a term in every memory should weigh 0")
	}
}

// shareOf is the reference relevance: the idf-weighted share over the given
// words, each counted separately, from FTS5 prefix matches over live memories.
func shareOf(t *testing.T, s *recallStore, words ...string) map[string]float64 {
	t.Helper()
	n := len(s.ids)
	hits := make([]map[string]bool, len(words))
	var total float64
	for i, w := range words {
		hits[i] = map[string]bool{}
		rows, err := s.e.db.Query(`SELECT id FROM memories_fts WHERE memories_fts MATCH ?`, `"`+w+`"*`)
		ok(t, err)
		for rows.Next() {
			var id string
			ok(t, rows.Scan(&id))
			hits[i][id] = true
		}
		ok(t, rows.Err())
		rows.Close()
		total += termWeight(n, len(hits[i]))
	}
	out := map[string]float64{}
	for i := range words {
		w := termWeight(n, len(hits[i]))
		for id := range hits[i] {
			out[id] += w
		}
	}
	for id := range out {
		out[id] /= total
	}
	return out
}

func sameShares(a, b map[string]float64) bool {
	if len(a) != len(b) {
		return false
	}
	for id, v := range a {
		if w, ok := b[id]; !ok || math.Abs(v-w) > 1e-12 {
			return false
		}
	}
	return true
}

func TestPrefixSubsumption(t *testing.T) {
	s := loadRecallStore(t, 0)
	// Equal hit sets: counted once.
	if got := s.relevance(t, "kubeconfig kube"); !sameShares(got, shareOf(t, s, "kubeconfig")) || !sameShares(got, s.relevance(t, "kubeconfig")) {
		t.Errorf("kubeconfig kube is not the single term kubeconfig: %v", got)
	}
	// Unequal hit sets: both tokens count.
	for _, tc := range []struct {
		q    string
		toks []string
	}{
		{"ci cilium upgrade", []string{"ci", "cilium", "upgrad"}},
		{"weekends week", []string{"weekend", "week"}},
		{"config configuration", []string{"config", "configur"}},
	} {
		words := strings.Fields(tc.q)
		if got := queryTokensOf(t, s.e, words...); !slices.Equal(got, tc.toks) {
			t.Errorf("tokens of %q = %q, want %q", tc.q, got, tc.toks)
		}
		if got := s.relevance(t, tc.q); !sameShares(got, shareOf(t, s, words...)) {
			t.Errorf("%q: relevance is not the share over %q", tc.q, words)
		}
	}
}

// A single-word query's candidates are exactly what the FTS5 prefix query
// matches, so df and matching come from the same rows.
func TestCandidatesEqualPrefixMatches(t *testing.T) {
	s := loadRecallStore(t, 0)
	seen := map[string]bool{}
	var words []string
	for _, line := range storeLines {
		for _, w := range wordRe.FindAllString(strings.ToLower(line), -1) {
			if !seen[w] {
				seen[w] = true
				words = append(words, w)
			}
		}
	}
	words = append(words, strings.Fields("café cafe 東京 configuration config outage outages deploying rotation ci e")...)
	for _, w := range words {
		toks := queryTokensOf(t, s.e, w)
		if len(toks) != 1 {
			t.Errorf("word %q gives tokens %q, want one", w, toks)
			continue
		}
		want, got := shareOf(t, s, w), s.relevance(t, w)
		for id := range want {
			if _, ok := got[id]; !ok {
				t.Errorf("word %q: MATCH finds %s, relevance does not", w, id)
			}
		}
		if len(got) != len(want) {
			t.Errorf("word %q: %d candidates, MATCH finds %d", w, len(got), len(want))
		}
	}
}
