package smem

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rahulsub/synapse-mem/judge"
)

// --- time bounds on import -------------------------------------------------

func TestImportBoundsTime(t *testing.T) {
	c := start()
	a := newEngine(t, "alice", c)
	b := newEngine(t, "bob", c)
	remote := DirRemote{Dir: t.TempDir()}

	// Bob's clock runs a day fast: his events are refused until ours catches up.
	fast := start()
	fast.advance(24 * time.Hour)
	b.Now = fast.now
	remember(t, b, "fact", "from the future")
	must[int](t)(b.Push(remote))
	rep := must[*ImportReport](t)(a.Pull(remote))
	if rep.Accepted != 0 || len(rep.Rejected) != 1 || !strings.Contains(rep.Rejected[0], "future") {
		t.Fatalf("future events must be refused: %+v", rep)
	}
	c.advance(24 * time.Hour)
	if rep := must[*ImportReport](t)(a.Pull(remote)); rep.Accepted != 2 {
		t.Fatalf("accepted once the clocks agree: %+v", rep)
	}

	// Carol's feed claims to be from a year ago: kept as signed, projected
	// at the clamp.
	cl := newEngine(t, "carol", start())
	old := start()
	old.advance(-365 * 24 * time.Hour)
	cl.Now = old.now
	m := remember(t, cl, "fact", "backdated claim")
	must[int](t)(cl.Push(remote))
	rep = must[*ImportReport](t)(a.Pull(remote))
	if rep.Clamped != 2 {
		t.Fatalf("backdated events should be clamped: %+v", rep)
	}
	ok(t, a.SetTrust(keyOf(t, cl), true, ""))
	mem := must[Memory](t)(a.Memory(m))
	if floor := c.now().Add(-a.Policy.Sync.MaxBackdate.D()); mem.RecordedAt.Before(floor.Add(-time.Second)) {
		t.Fatalf("recorded at %s, before the clamp %s", mem.RecordedAt, floor)
	}
	if !must[*VerifyReport](t)(a.Verify()).OK {
		t.Fatal("clamping must not touch what was signed")
	}
	before := dumpViews(t, a)
	ok(t, a.Rebuild())
	if dumpViews(t, a) != before {
		t.Fatal("the clamp must survive a rebuild")
	}
}

// --- forks ---------------------------------------------------------------

func TestTornFeedLineIsSkippedAndRepaired(t *testing.T) {
	c := start()
	a := newEngine(t, "alice", c)
	b := newEngine(t, "bob", c)
	remote := DirRemote{Dir: t.TempDir()}
	remember(t, b, "fact", "one")
	must[int](t)(b.Push(remote))
	// A push cut off mid-line.
	f, _ := os.OpenFile(remote.feedPath(b.Replica()), os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(`{"id":"evt-trunc","replica":"`)
	f.Close()
	if rep, err := a.Pull(remote); err != nil || rep.Accepted != 2 {
		t.Fatalf("complete events before a torn line still import: %+v %v", rep, err)
	}
	remember(t, b, "fact", "two")
	must[int](t)(b.Push(remote)) // repairs the tail, then appends
	if rep := must[*ImportReport](t)(a.Pull(remote)); rep.Accepted != 1 || len(rep.Rejected) != 0 {
		t.Fatalf("after repair: %+v", rep)
	}
}

func TestNewStoreRaceGetsOneReplica(t *testing.T) {
	path := filepath.Join(t.TempDir(), "smem.db")
	ids := make([]string, 8)
	var wg sync.WaitGroup
	for i := range ids {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e, err := Open(path)
			if err != nil {
				t.Error(err)
				return
			}
			ids[i] = e.Replica()
			e.Close()
		}()
	}
	wg.Wait()
	for _, id := range ids {
		if id != ids[0] {
			t.Fatalf("processes opening a new store must agree on one replica: %v", ids)
		}
	}
}

func TestCopiedStoreBecomesNewReplica(t *testing.T) {
	c := start()
	e := newEngine(t, "alice", c)
	remember(t, e, "fact", "before the backup")
	orig := e.Replica()
	ok(t, e.Close())
	copyPath := filepath.Join(t.TempDir(), "restored.db")
	b, _ := os.ReadFile(e.Path())
	os.WriteFile(copyPath, b, 0o644)

	restored := must[*Engine](t)(Open(copyPath))
	defer restored.Close()
	restored.Now, restored.KeyDir, restored.Actor = c.now, e.KeyDir, "alice"
	if restored.Replica() == orig {
		t.Fatal("a copy that kept the replica id would fork its chain")
	}
	remember(t, restored, "fact", "after the restore")
	if !must[*VerifyReport](t)(restored.Verify()).OK {
		t.Fatal("verify")
	}
	again := must[*Engine](t)(Open(copyPath))
	defer again.Close()
	if again.Replica() != restored.Replica() {
		t.Fatal("reopening the same file keeps its replica")
	}
}

// --- identity ----------------------------------------------------------------

func TestLostKeyDirFailsLoudly(t *testing.T) {
	c := start()
	e := newEngine(t, "agent-7", c)
	remember(t, e, "fact", "signed with the first key")
	ok(t, os.RemoveAll(e.KeyDir)) // the agent restarted with a fresh $HOME
	e.keys = map[string]ed25519.PrivateKey{}
	_, err := e.Remember(MemoryInput{Kind: "fact", Content: "would be signed by a new identity"})
	if err == nil || !strings.Contains(err.Error(), "SMEM_KEY_DIR") {
		t.Fatalf("a lost key dir must not silently create a new identity: %v", err)
	}
	e.AllowNewKey = true
	remember(t, e, "fact", "deliberately a new key")
	if n := len(must[[]Key](t)(e.Keys())); n != 2 {
		t.Fatalf("keys: %d", n)
	}
}

// --- evidence policy -----------------------------------------------------------

func TestEvidenceStaysInTheProject(t *testing.T) {
	c := start()
	e := newEngine(t, "alice", c)
	root := filepath.Dir(filepath.Dir(e.Path()))
	os.WriteFile(filepath.Join(root, "app.conf"), []byte("port 9090"), 0o644)
	os.WriteFile(filepath.Join(root, ".env"), []byte("DB_PASSWORD=x"), 0o644)
	outside := filepath.Join(t.TempDir(), "secret.txt")
	os.WriteFile(outside, []byte("outside the project"), 0o644)
	os.Symlink(outside, filepath.Join(root, "link.txt"))

	pol := DefaultFactCheckPolicy().Evidence
	for ref, want := range map[string]string{
		"app.conf":           "port 9090",
		".env":               "denied",
		outside:              "outside the project",
		"link.txt":           "outside the project",
		"../../etc/passwd":   "",
		"/proc/self/environ": "",
	} {
		text, err := readEvidenceFile(root, ref, pol)
		got := text
		if err != nil {
			got = err.Error()
		}
		if ref == "app.conf" && got != want {
			t.Errorf("%s: %q", ref, got)
		}
		if ref != "app.conf" && err == nil {
			t.Errorf("%s must not be readable as evidence, got %q", ref, text)
		}
		if want == "denied" && !strings.Contains(got, "denied") {
			t.Errorf("%s: %q", ref, got)
		}
	}
	// Allow can narrow; deny can't be configured away.
	narrow := FactCheckPolicy{Evidence: EvidencePolicy{Allow: []string{"docs/**"}, Deny: []string{"docs/private/**"}}}.withDefaults().Evidence
	if _, err := readEvidenceFile(root, "app.conf", narrow); err == nil {
		t.Error("allow should narrow")
	}
	if !contains(narrow.Deny, "**/.env") || !contains(narrow.Deny, "docs/private/**") {
		t.Errorf("configured denials add to the defaults: %v", narrow.Deny)
	}
}

func TestCommitSourcesCantInjectGitOptions(t *testing.T) {
	c := start()
	e := newEngine(t, "alice", c)
	src := must[string](t)(e.CaptureSource("commit", "--output=/tmp/pwned", "", ""))
	m := must[string](t)(e.Remember(MemoryInput{Kind: "fact", Content: "x", DerivedFrom: []string{src}}))
	evs := must[[]Evidence](t)(e.gatherEvidence(must[Memory](t)(e.Memory(m)), DefaultFactCheckPolicy()))
	if len(evs) != 0 {
		t.Fatalf("a non-hash commit ref must be ignored: %+v", evs)
	}
}

// --- fact-check agreement, cache, budget -------------------------------------

func TestNoSingleJudgeActs(t *testing.T) {
	c := start()
	e := newEngine(t, "alice", c)
	m := remember(t, e, "fact", "the release is on the 14th")
	remember(t, e, "fact", "the release moved to the 21st")

	jev := &scripted{name: "jev", choice: "contradicts", conf: 0.97, subject: 0.95}
	e.Judges = stages(jev)
	res := must[*FactCheckResult](t)(e.FactCheck(context.Background(), m, true))
	if res.Action != "review" || status(t, e, m) != "active" {
		t.Fatalf("Jev alone (weak on dates and numbers) must not change a memory: %+v", res)
	}

	// A second judge that agrees: now it acts. Claude is asked even though
	// Jev was confident, to make up the second check.
	claude := &scripted{name: "claude", choice: "contradicts", conf: 0.9, subject: 0.9}
	e.Judges = stages(jev, claude)
	c.advance(time.Hour)
	e.FactCheckPolicy.CacheTTL = -1
	res = must[*FactCheckResult](t)(e.FactCheck(context.Background(), m, true))
	if res.Action != "suspected" || len(res.Trail) != 2 {
		t.Fatalf("two agreeing checks act: %+v", res)
	}

	// A checker and a judge count as two.
	m2 := remember(t, e, "fact", "the api listens on port 8080")
	remember(t, e, "fact", "the api port is set in the deploy manifest")
	e.Checkers = []Checker{CheckFunc("port", func(context.Context, Claim) (CheckResult, error) {
		return CheckResult{Verdict: &Verdict{Label: Contradicted, Reason: "config says 9090"}}, nil
	})}
	e.Judges = stages(&scripted{name: "jev", choice: "contradicts", conf: 0.9, subject: 0.9})
	res = must[*FactCheckResult](t)(e.FactCheck(context.Background(), m2, true))
	if res.Action != "suspected" || res.DecidedBy != "checker:port" {
		t.Fatalf("checker + judge: %+v", res)
	}
}

type counting struct {
	scripted
	calls int
}

func (c *counting) Ask(ctx context.Context, r judge.Request) (*judge.Result, error) {
	c.calls++
	return c.scripted.Ask(ctx, r)
}

func TestFactCheckCacheAndBudget(t *testing.T) {
	c := start()
	e := newEngine(t, "alice", c)
	m := remember(t, e, "fact", "builds run on m5")
	remember(t, e, "fact", "builds run on the m5 pool")
	j := &counting{scripted: scripted{name: "jev", choice: "supports", conf: 0.95, subject: 0.9}}
	e.Judges = stages(j)
	must[*FactCheckResult](t)(e.FactCheck(context.Background(), m, false))
	res := must[*FactCheckResult](t)(e.FactCheck(context.Background(), m, false))
	if !res.Cached || j.calls != 1 {
		t.Fatalf("unchanged input should reuse the judgment: calls %d, %+v", j.calls, res)
	}

	e.FactCheckPolicy.DailyBudget = 1
	m2 := remember(t, e, "fact", "builds run on m6")
	res = must[*FactCheckResult](t)(e.FactCheck(context.Background(), m2, false))
	if j.calls != 1 || len(res.Errors) == 0 || !strings.Contains(res.Errors[0], "budget") {
		t.Fatalf("over budget: no judge call, and say why: calls %d %+v", j.calls, res)
	}
	c.advance(25 * time.Hour)
	must[*FactCheckResult](t)(e.FactCheck(context.Background(), m2, false))
	if j.calls != 2 {
		t.Fatal("budget renews after 24 hours")
	}
}

// --- recall and context ---------------------------------------------------------

func TestActiveClockKeepsMemoryThroughIdleWeeks(t *testing.T) {
	salienceAfterIdle := func(clock string) float64 {
		c := start()
		e := newEngine(t, "alice", c)
		e.Policy.Decay.Clock = clock
		m := remember(t, e, "fact", "the staging db is shared")
		c.advance(14 * 24 * time.Hour) // the agent is off for two weeks
		for _, h := range must[[]Scored](t)(e.Recall(RecallQuery{Text: "staging", NoRecord: true})) {
			if h.ID == m {
				return h.Salience
			}
		}
		return 0
	}
	wall, active := salienceAfterIdle("wall"), salienceAfterIdle("active")
	if active <= wall*1.5 {
		t.Fatalf("idle time should not count on the active clock: wall %.3f active %.3f", wall, active)
	}
	c := start()
	e := newEngine(t, "alice", c)
	e.Policy.Decay.Clock = "active"
	remember(t, e, "fact", "x")
	c.advance(14 * 24 * time.Hour)
	if out := must[[]Scored](t)(e.Sweep(0.99, 7*24*time.Hour, true)); len(out) != 0 {
		t.Fatal("idle time doesn't count toward sweep's idle requirement either")
	}
}

func TestContradictionsResetOnReconfirm(t *testing.T) {
	c := start()
	e := newEngine(t, "alice", c)
	m := remember(t, e, "fact", "the cache ttl is 60s")
	conf := func() float64 {
		return must[[]Scored](t)(e.Recall(RecallQuery{Text: "cache ttl", NoRecord: true}))[0].Confidence
	}
	base := conf()
	ok(t, e.Signal(m, "contradicted", "saw 30s somewhere"))
	if conf() > base*0.6 {
		t.Fatal("a contradiction halves confidence")
	}
	c.advance(time.Minute)
	ok(t, e.Reconfirm(m, 0, "checked the config: 60s"))
	if conf() < base*0.9 {
		t.Fatalf("reconfirming answers earlier contradictions: %.3f vs %.3f", conf(), base)
	}
}

func TestContextDoesNotReinforceAndRespectsScope(t *testing.T) {
	c := start()
	e := newEngine(t, "alice", c)
	e.Policy.Scopes.Read = []string{"project:dojo*"}
	mine := must[string](t)(e.Remember(MemoryInput{Kind: "fact", Content: "dojo uses dojo- bead ids", Scope: "project:dojo"}))
	global := remember(t, e, "fact", "prefer small PRs")
	other := must[string](t)(e.Remember(MemoryInput{Kind: "fact", Content: "billing uses stripe", Scope: "project:billing"}))
	ctx := must[string](t)(e.Context(0))
	if !strings.Contains(ctx, mine) || !strings.Contains(ctx, global) || strings.Contains(ctx, other) {
		t.Fatalf("context should follow scopes.read:\n%s", ctx)
	}
	var n int
	ok(t, e.db.QueryRow(`SELECT COUNT(*) FROM accesses WHERE signal = 'retrieved'`).Scan(&n))
	if n != 0 {
		t.Fatalf("being shown is not being used: %d retrieved accesses", n)
	}
	if hits := must[[]Scored](t)(e.Recall(RecallQuery{Text: "stripe", NoRecord: true, AllScopes: true})); len(hits) != 1 {
		t.Fatal("AllScopes looks everywhere")
	}
	e.Policy.Scopes.Write = "project:dojo"
	id := remember(t, e, "fact", "new memories take the write scope")
	if must[Memory](t)(e.Memory(id)).Scope != "project:dojo" {
		t.Fatal("scopes.write")
	}
}

func TestRepeatedRecallIsLoggedOnce(t *testing.T) {
	c := start()
	e := newEngine(t, "alice", c)
	remember(t, e, "fact", "the queue is sqs")
	for i := 0; i < 5; i++ {
		must[[]Scored](t)(e.Recall(RecallQuery{Text: "queue"}))
	}
	if n := len(must[[]Event](t)(e.Events("", evRecall, 50))); n != 1 {
		t.Fatalf("identical recalls in a session within the window: %d logged", n)
	}
	c.advance(time.Hour)
	must[[]Scored](t)(e.Recall(RecallQuery{Text: "queue"}))
	if n := len(must[[]Event](t)(e.Events("", evRecall, 50))); n != 2 {
		t.Fatal("outside the window it is logged again")
	}
}

// --- hooks -------------------------------------------------------------------

func TestSpoolDrainAndUnambiguousLinking(t *testing.T) {
	c := start()
	e := newEngine(t, "claude-code", c)
	e.Session = "s1"
	dec := must[string](t)(func() (string, error) {
		id, _, err := e.Decide(DecisionInput{Question: "retry?", Choice: "yes"})
		return id, err
	}())
	cfg := DefaultConfig()
	t.Setenv("SMEM_ACTOR", "claude-code")
	spoolNow = c.now
	defer func() { spoolNow = time.Now }()
	in := HookInput{SessionID: "s1", ToolName: "Bash", ToolInput: json.RawMessage(`{"command":"export API_TOKEN=abcdef123456; make"}`)}
	ok(t, SpoolToolUse(e.Path(), in, cfg, false))
	ok(t, SpoolToolUse(e.Path(), HookInput{SessionID: "s1", ToolName: "Read"}, cfg, false))
	if e.SpoolBacklog() != 1 {
		t.Fatal("read-only tools aren't spooled")
	}
	spooled, _ := filepath.Glob(filepath.Join(filepath.Dir(e.Path()), "spool", "*.json"))
	if b, _ := os.ReadFile(spooled[0]); strings.Contains(string(b), "abcdef123456") {
		t.Fatal("the spool is redacted before it touches the disk")
	}
	if n := must[int](t)(e.DrainSpool()); n != 1 || e.SpoolBacklog() != 0 {
		t.Fatalf("drained %d", n)
	}
	acts := must[[]Action](t)(e.actions(`tool = 'Bash'`))
	if len(acts) != 1 || acts[0].DecisionID != dec || acts[0].Session != "s1" {
		t.Fatalf("one decision in the session: link it: %+v", acts)
	}

	// Two decisions in the window (parallel subagents): don't guess.
	e.Decide(DecisionInput{Question: "other subagent's call", Choice: "z"})
	ok(t, SpoolToolUse(e.Path(), in, cfg, false))
	must[int](t)(e.DrainSpool())
	acts = must[[]Action](t)(e.actions(`tool = 'Bash'`))
	if len(acts) != 2 || acts[1].DecisionID != "" {
		t.Fatalf("ambiguous: no link: %+v", acts)
	}
}

func TestSessionsFollowTheProcessTree(t *testing.T) {
	c := start()
	e := newEngine(t, "alice", c)
	ok(t, e.SetCurrentSession("cc-1"))
	if got := e.CurrentSession(); got != "cc-1" {
		t.Fatalf("a process sharing ancestors finds the session: %q", got)
	}
	if got := e.SessionFor([]int{999999}); got != "" {
		t.Fatal("an unrelated process finds nothing")
	}
}

// --- config ------------------------------------------------------------------

func TestProjectConfigCannotRunCode(t *testing.T) {
	c := start()
	e := newEngine(t, "alice", c)
	t.Setenv("SMEM_CONFIG", filepath.Join(t.TempDir(), "local.json"))
	for _, body := range []string{
		`{"checkers":[{"name":"x","command":["sh","-c","curl evil"]}]}`,
		`{"endpoints":{"claude":"https://evil.example"}}`,
		`{"trust":{"keys":["key-0123"]}}`,
		`{"keys":{"dir":"/tmp"}}`,
	} {
		os.WriteFile(ConfigPath(e.Path()), []byte(body), 0o644)
		if _, err := LoadConfigFor(e.Path()); err == nil || !strings.Contains(err.Error(), "local config") {
			t.Errorf("%s: project config must refuse it: %v", body, err)
		}
	}
	os.WriteFile(ConfigPath(e.Path()), []byte(`{"beads":{"prefixes":["dojo"]},"factcheck":{"cache_ttl":"7d"},"scopes":{"read":["team"]}}`), 0o644)
	os.WriteFile(os.Getenv("SMEM_CONFIG"), []byte(`{"actor":"dojo-agent-3","scopes":{"read":["team","agent:3"]},
		"checkers":[{"name":"probe","command":["true"]}]}`), 0o644)
	cfg := must[*Config](t)(LoadConfigFor(e.Path()))
	if cfg.FactCheck.CacheTTL.D() != 7*24*time.Hour || cfg.Actor != "dojo-agent-3" || len(cfg.Checkers) != 1 ||
		len(cfg.Scopes.Read) != 2 || cfg.Beads.Prefixes[0] != "dojo" || cfg.Hooks.LinkDecisions != "unambiguous" {
		t.Fatalf("project, then local, over the defaults: %+v", cfg)
	}
	os.WriteFile(ConfigPath(e.Path()), []byte(`{"factchek":{}}`), 0o644)
	if _, err := LoadConfigFor(e.Path()); err == nil {
		t.Error("a misspelled key is an error, not silently ignored")
	}
}

func TestBeadPrefixesFromConfigAndBeads(t *testing.T) {
	c := start()
	e := newEngine(t, "alice", c)
	root := filepath.Dir(filepath.Dir(e.Path()))
	os.MkdirAll(filepath.Join(root, ".beads"), 0o755)
	os.WriteFile(filepath.Join(root, ".beads", "config.yaml"), []byte("issue-prefix: \"dojo\"\n"), 0o644)
	ok(t, e.Configure(DefaultConfig()))
	for ref, want := range map[string]bool{"dojo-j6lv": true, "dojo-j6lv.1": true, "dojo-j6lv.1.2": true, "bd-a1b2": true,
		"app.env": false, "docs/dojo-j6lv.md": false, "other-x1": false} {
		if e.IsBead(ref) != want {
			t.Errorf("IsBead(%q) = %v", ref, !want)
		}
	}
	dec, _, err := e.Decide(DecisionInput{Question: "which queue?", Choice: "sqs", Evidence: []string{"dojo-j6lv.1"}})
	ok(t, err)
	if tr := must[*Trace](t)(e.Why("dojo-j6lv.1")); len(tr.Decisions) != 1 || tr.Decisions[0].Decision.ID != dec {
		t.Fatal("why <bead> finds decisions that cite it as evidence")
	}
	src := must[string](t)(e.CaptureSource("", "dojo-j6lv.1", "", ""))
	if s := must[*Trace](t)(e.Why(src)).Source; s.Kind != "bead" {
		t.Fatalf("a child bead id is a bead, not a file: %+v", s)
	}
	p := DefaultConfig()
	p.Beads = BeadsPolicy{Prefixes: []string{"acme"}}
	ok(t, e.Configure(p))
	if !e.IsBead("acme-x9") || e.IsBead("dojo-j6lv") {
		t.Fatal("prefixes come from config; detect off ignores .beads")
	}
}

func TestPullOnlyRemoteIsNeverWritten(t *testing.T) {
	c := start()
	curator := newEngine(t, "curator", c)
	agent := newEngine(t, "agent", c)
	team := t.TempDir()
	remember(t, curator, "procedure", "deploys go through the release train")
	must[int](t)(curator.Push(DirRemote{Dir: team}))
	ok(t, agent.AddRemote("team", team, true))
	r := must[map[string]DirRemote](t)(agent.Remotes())["team"]
	remember(t, agent, "fact", "my own note")
	if _, n, err := agent.Sync(r); err != nil || n != 0 {
		t.Fatalf("pull-only: %d pushed, %v", n, err)
	}
	if _, err := os.Stat(r.feedPath(agent.Replica())); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("nothing written to a pull-only remote")
	}
}

// --- judges through a gateway -----------------------------------------------------

func TestClaudeThroughGatewayHeaders(t *testing.T) {
	var got http.Header
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(429)
		io.WriteString(w, `{"type":"error","error":{"type":"rate_limit_error","message":"x"}}`)
	}))
	defer srv.Close()
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "gateway-token")
	t.Setenv("ANTHROPIC_BASE_URL", srv.URL)
	t.Setenv("ANTHROPIC_CUSTOM_HEADERS", "x-gateway-key: gw-agent-key-123456\nx-team: acme")
	t.Setenv("SMEM_JUDGE_MODEL", "my-gateway/claude-haiku-5-5")
	t.Setenv("TYPESAFE_API_KEY", "")
	t.Setenv("OPENROUTER_API_KEY", "")

	c := start()
	e := newEngine(t, "alice", c)
	cfg := DefaultConfig()
	cfg.Judges.Claude.MaxAttempts = 1
	ok(t, e.Configure(cfg))
	if names := e.Judges.Names(); len(names) != 1 || names[0] != "claude" {
		t.Fatalf("base URL plus custom headers enable Claude: %v", names)
	}
	m := remember(t, e, "fact", "the release is on the 14th")
	remember(t, e, "fact", "the release moved to the 21st")
	res := must[*FactCheckResult](t)(e.FactCheck(context.Background(), m, true))

	if got.Get("x-gateway-key") != "gw-agent-key-123456" || got.Get("x-team") != "acme" || got.Get("Authorization") != "Bearer gateway-token" {
		t.Fatalf("headers: %v", got)
	}
	if body["model"] != "my-gateway/claude-haiku-5-5" {
		t.Fatalf("SMEM_JUDGE_MODEL: %v", body["model"])
	}
	sys, _ := json.Marshal(body["system"])
	if strings.Contains(string(sys), "Claude Code") {
		t.Fatal("smem does not present itself as Claude Code")
	}
	if !res.NotJudged || res.Action != "not-judged" || !strings.Contains(res.Verdict.Reason, "HTTP 429") {
		t.Fatalf("a failed judge must say so, not look like no judge: %+v", res)
	}
	rv := must[*Review](t)(e.Review())
	if len(rv.Judges) != 1 || rv.Judges[0].LastStatus != 429 || rv.Judges[0].OK != 0 {
		t.Fatalf("review should show the failing judge: %+v", rv.Judges)
	}

	// The per-agent key is a secret: redacted on its own, never given to checkers.
	r := must[*Redactor](t)(NewRedactor(RedactionPolicy{}))
	if out := r.Redact("key is gw-agent-key-123456"); strings.Contains(out, "gw-agent") {
		t.Fatalf("custom header value leaked: %q", out)
	}
	for _, kv := range checkerEnv([]string{"ANTHROPIC_CUSTOM_HEADERS", "ANTHROPIC_BASE_URL"}) {
		if strings.HasPrefix(kv, "ANTHROPIC_") {
			t.Fatalf("checkers must not get %s", kv)
		}
	}
}

func TestConfirmationRaisesConfidence(t *testing.T) {
	c := start()
	e := newEngine(t, "alice", c)
	m := remember(t, e, "fact", "the cache ttl is 60s")
	conf := func() float64 {
		return must[[]Scored](t)(e.Recall(RecallQuery{Text: "cache ttl", NoRecord: true}))[0].Confidence
	}
	if got := conf(); got < 0.79 || got > 0.81 {
		t.Fatalf("starts at 0.80: %.3f", got)
	}
	ok(t, e.Signal(m, "confirmed", "checked the config"))
	if got := conf(); got < 0.89 || got > 0.91 {
		t.Fatalf("one confirmation halves the doubt: %.3f", got)
	}
	ok(t, e.Signal(m, "confirmed", "checked again"))
	if got := conf(); got < 0.94 {
		t.Fatalf("two: %.3f", got)
	}
	if ctx := must[string](t)(e.Context(0)); !strings.Contains(ctx, "conf 0.95") {
		t.Fatalf("the context view shows it:\n%s", ctx)
	}
	// The boost is in the event: a replica with another setting projects the same.
	e.Policy.Confidence.ConfirmBoost = 0
	before := dumpViews(t, e)
	ok(t, e.Rebuild())
	if dumpViews(t, e) != before {
		t.Fatal("replay must not depend on local config")
	}
}
