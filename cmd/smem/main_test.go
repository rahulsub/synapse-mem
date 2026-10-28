package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// Every command in the usage text must be registered, and vice versa.
func TestUsageMatchesCommands(t *testing.T) {
	listed := map[string]bool{}
	// "  name ..." and "  push [remote] | pull [remote]"
	for _, m := range regexp.MustCompile(`(?m)(?:^  |\| )([a-z][a-z-]+)`).FindAllStringSubmatch(usage, -1) {
		listed[m[1]] = true
	}
	for name := range listed {
		if _, ok := commands[name]; !ok && name != "version" {
			t.Errorf("%q is in the usage but not registered", name)
		}
	}
	for name := range commands {
		if !listed[name] {
			t.Errorf("%q is registered but not in the usage", name)
		}
	}
}

func TestMCPInitCreatesIgnoredStore(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("SMEM_DB", "")
	t.Setenv("SMEM_KEY_DIR", filepath.Join(dir, "keys"))
	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"memory_remember","arguments":{"content":"x","kind":"fact"}}}` + "\n")
	var out bytes.Buffer
	if err := run([]string{"mcp", "--init"}, in, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "mem-") {
		t.Fatalf("mcp: %s", out.String())
	}
	b, err := os.ReadFile(filepath.Join(dir, ".smem", ".gitignore"))
	if err != nil || !strings.Contains(string(b), "!config.json") {
		t.Fatalf(".smem/.gitignore: %q %v", b, err)
	}
	// Without --init and without a store, mcp refuses rather than scattering stores.
	t.Chdir(t.TempDir())
	if err := run([]string{"mcp"}, strings.NewReader(""), &out); err == nil {
		t.Fatal("mcp without a store or --init should fail")
	}
}

func TestHookUsesTheSessionsDirectory(t *testing.T) {
	proj := t.TempDir()
	t.Setenv("SMEM_DB", "")
	t.Setenv("SMEM_CONFIG", filepath.Join(t.TempDir(), "none.json"))
	t.Setenv("SMEM_KEY_DIR", filepath.Join(t.TempDir(), "keys"))
	t.Setenv("SMEM_ACTOR", "claude-code")
	t.Chdir(proj)
	var out bytes.Buffer
	if err := run([]string{"init"}, strings.NewReader(""), &out); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"remember", "--kind", "fact", "deploys use the release train"}, strings.NewReader(""), &out); err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir()) // the hook process starts somewhere else
	hook := func(event, body string) string {
		var o bytes.Buffer
		if err := run([]string{"hook", event}, strings.NewReader(body), &o); err != nil {
			t.Fatal(err)
		}
		return o.String()
	}
	start := `{"session_id":"s1","cwd":"` + proj + `","source":"%s"}`
	if got := hook("session-start", strings.Replace(start, "%s", "startup", 1)); !strings.Contains(got, "release train") {
		t.Fatalf("session-start should find the store from the input cwd:\n%s", got)
	}
	if got := hook("session-start", strings.Replace(start, "%s", "compact", 1)); got != "" {
		t.Fatalf("context.on excludes compact by default:\n%s", got)
	}
	hook("post-tool-use", `{"session_id":"s1","cwd":"`+proj+`","tool_name":"Bash","tool_input":{"command":"make test"}}`)
	if spooled, _ := filepath.Glob(filepath.Join(proj, ".smem", "spool", "*.json")); len(spooled) != 1 {
		t.Fatalf("post-tool-use spools in the session's store: %v", spooled)
	}
}

func TestInitClaudeCodeKeepsExistingSettings(t *testing.T) {
	proj := t.TempDir()
	t.Chdir(proj)
	t.Setenv("SMEM_DB", "")
	t.Setenv("SMEM_KEY_DIR", filepath.Join(t.TempDir(), "keys"))
	os.MkdirAll(filepath.Join(proj, ".claude"), 0o755)
	os.WriteFile(filepath.Join(proj, ".claude", "settings.json"), []byte(`{"permissions":{"allow":["Bash(make:*)"]}}`), 0o644)
	var out bytes.Buffer
	for i := 0; i < 2; i++ { // idempotent
		if err := run([]string{"init", "--claude-code"}, strings.NewReader(""), &out); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := os.ReadFile(filepath.Join(proj, ".claude", "settings.json"))
	if !strings.Contains(string(b), "Bash(make:*)") || strings.Count(string(b), "smem hook session-start") != 1 {
		t.Fatalf("settings: %s", b)
	}
	m, _ := os.ReadFile(filepath.Join(proj, ".mcp.json"))
	if !strings.Contains(string(m), `"mcp"`) {
		t.Fatalf(".mcp.json: %s", m)
	}
}

func TestDoctorFlagsALostKey(t *testing.T) {
	proj := t.TempDir()
	t.Chdir(proj)
	keys := filepath.Join(t.TempDir(), "keys")
	t.Setenv("SMEM_DB", "")
	t.Setenv("SMEM_KEY_DIR", keys)
	t.Setenv("SMEM_ACTOR", "agent-1")
	var out bytes.Buffer
	run([]string{"init"}, strings.NewReader(""), &out)
	run([]string{"remember", "--kind", "fact", "x"}, strings.NewReader(""), &out)
	os.RemoveAll(keys)
	out.Reset()
	err := run([]string{"doctor"}, strings.NewReader(""), &out)
	if err == nil || !strings.Contains(out.String(), "private key is missing") {
		t.Fatalf("doctor:\n%s", out.String())
	}
	if err := run([]string{"remember", "--kind", "fact", "y"}, strings.NewReader(""), &out); err == nil {
		t.Fatal("writing with a lost key must fail, not mint a new identity")
	}
}

// newStore initializes a store in a fresh directory and returns a runner
// for smem commands against it.
func newStore(t *testing.T) func(stdin string, args ...string) (string, error) {
	t.Helper()
	t.Chdir(t.TempDir())
	t.Setenv("SMEM_DB", "")
	t.Setenv("SMEM_CONFIG", filepath.Join(t.TempDir(), "none.json"))
	t.Setenv("SMEM_KEY_DIR", filepath.Join(t.TempDir(), "keys"))
	t.Setenv("SMEM_ACTOR", "agent-1")
	smem := func(stdin string, args ...string) (string, error) {
		var out bytes.Buffer
		err := run(args, strings.NewReader(stdin), &out)
		return out.String(), err
	}
	if _, err := smem("", "init"); err != nil {
		t.Fatal(err)
	}
	return smem
}

func TestRecallInjected(t *testing.T) {
	smem := newStore(t)
	if _, err := smem("", "remember", "--kind", "fact", "deploys use the release train"); err != nil {
		t.Fatal(err)
	}
	if out, err := smem("", "recall", "--injected", "deploys"); err != nil || !strings.Contains(out, "release train") {
		t.Fatalf("recall --injected: %v\n%s", err, out)
	}
	out, err := smem("", "log", "--type", "recall", "--json")
	var evs []struct {
		Payload struct{ Injected bool }
	}
	if err != nil || json.Unmarshal([]byte(out), &evs) != nil || len(evs) != 1 || !evs[0].Payload.Injected {
		t.Fatalf("recall --injected should log an injected recall: %v\n%s", err, out)
	}
	if _, err := smem("", "recall", "--injected", "--no-record", "deploys"); err == nil {
		t.Fatal("--injected with --no-record should be refused")
	}
}

// lastPayload decodes the payload of the latest event of type typ into v.
func lastPayload(t *testing.T, smem func(string, ...string) (string, error), typ string, v any) {
	t.Helper()
	out, err := smem("", "log", "--type", typ, "--limit", "1", "--json")
	var evs []struct{ Payload json.RawMessage }
	if err != nil || json.Unmarshal([]byte(out), &evs) != nil || len(evs) != 1 || json.Unmarshal(evs[0].Payload, v) != nil {
		t.Fatalf("log --type %s: %v\n%s", typ, err, out)
	}
}

func TestContentFromStdin(t *testing.T) {
	smem := newStore(t)
	old := func() string {
		id, err := smem("", "remember", "--kind", "fact", "deploys go out on fridays")
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(id)
	}
	for _, tc := range []struct {
		name, typ, field, text string
		args                   func(content string) []string
	}{
		{"remember", "memory.asserted", "content", "deploys use the release train",
			func(s string) []string { return []string{"remember", "--kind", "fact", s} }},
		{"remember redacts", "memory.asserted", "content", "deploy --api-key abcdef123456 --region us",
			func(s string) []string { return []string{"remember", "--kind", "fact", s} }},
		{"supersede", "memory.asserted", "content", "deploys go out on tuesdays",
			func(s string) []string { return []string{"supersede", old(), s} }},
		{"failure", "failure.recorded", "summary", "migration ran twice",
			func(s string) []string { return []string{"failure", "double-migration", s} }},
		{"rules propose", "rule.proposed", "text", "run migrations once",
			func(s string) []string {
				return []string{"rules", "propose", "--why", "requested", "--by", "alice", "--quote", "only once", s}
			}},
	} {
		if _, err := smem("", tc.args(tc.text)...); err != nil {
			t.Fatalf("%s from argv: %v", tc.name, err)
		}
		var fromArgv map[string]any
		lastPayload(t, smem, tc.typ, &fromArgv)
		if _, err := smem(tc.text+"\n", tc.args("-")...); err != nil {
			t.Fatalf("%s from stdin: %v", tc.name, err)
		}
		var fromStdin map[string]any
		lastPayload(t, smem, tc.typ, &fromStdin)
		if fromStdin["id"] == fromArgv["id"] {
			t.Fatalf("%s from stdin recorded nothing new", tc.name)
		}
		if fromStdin[tc.field] != fromArgv[tc.field] {
			t.Errorf("%s: stdin stored %q, argv stored %q", tc.name, fromStdin[tc.field], fromArgv[tc.field])
		}
		if strings.Contains(fmt.Sprint(fromStdin[tc.field]), "abcdef123456") {
			t.Errorf("%s: a secret on stdin reached the log", tc.name)
		}
	}
	if _, err := smem("", "remember", "--kind", "fact", "-"); err == nil {
		t.Error("remember - with nothing on stdin should fail")
	}
}

func TestDecideAndActionInputFromStdin(t *testing.T) {
	smem := newStore(t)
	mem, err := smem("", "remember", "--kind", "fact", "the orders table is append-only")
	if err != nil {
		t.Fatal(err)
	}
	mem = strings.TrimSpace(mem)
	type decision struct {
		ID                                string
		Question, Choice, Rationale, Bead string
		Rejected                          []map[string]string
		Assumptions                       []struct {
			Statement string
			CheckHint string `json:"check_hint"`
		}
		Used, Evidence []string
	}
	if _, err := smem("", "decide", "--question", "how to fix totals?", "--choice", "correction rows", "--why", "append-only",
		"--reject", "update in place|breaks the audit", "--assume", "no consumer sums raw rows|grep consumers",
		"--used", mem, "--evidence", mem, "--bead", "bd-7"); err != nil {
		t.Fatal(err)
	}
	var fromFlags decision
	lastPayload(t, smem, "decision.made", &fromFlags)
	input := `{"question":"how to fix totals?","choice":"correction rows","why":"append-only",
		"rejected":[{"option":"update in place","reason":"breaks the audit"}],
		"assumptions":[{"statement":"no consumer sums raw rows","check":"grep consumers"}],
		"used":["` + mem + `"],"evidence":["` + mem + `"],"bead":"bd-7"}`
	if _, err := smem(input, "decide", "--input", "-"); err != nil {
		t.Fatal(err)
	}
	var fromInput decision
	lastPayload(t, smem, "decision.made", &fromInput)
	if fromInput.ID == fromFlags.ID {
		t.Fatal("decide --input - recorded nothing new")
	}
	fromInput.ID, fromFlags.ID = "", ""
	if !reflect.DeepEqual(fromInput, fromFlags) || fromInput.Rationale == "" || len(fromInput.Assumptions) != 1 {
		t.Fatalf("decide --input - should match the flags:\ninput %+v\nflags %+v", fromInput, fromFlags)
	}

	if _, err := smem(`{"tool":"deploy","summary":"shipped totals fix","bead":"bd-7"}`, "action", "--input", "-"); err != nil {
		t.Fatal(err)
	}
	var act struct{ Tool, Summary, Bead string }
	lastPayload(t, smem, "action.recorded", &act)
	if act.Tool != "deploy" || act.Summary != "shipped totals fix" || act.Bead != "bd-7" {
		t.Fatalf("action --input -: %+v", act)
	}

	for _, tc := range []struct {
		name, stdin string
		args        []string
	}{
		{"malformed decision", `{"question":`, []string{"decide", "--input", "-"}},
		{"unknown field", `{"question":"q","choice":"c","rationale":"r"}`, []string{"decide", "--input", "-"}},
		{"flag and input", `{"choice":"c"}`, []string{"decide", "--question", "q", "--input", "-"}},
		{"input from a file", `{}`, []string{"decide", "--input", "decision.json"}},
		{"malformed action", `not json`, []string{"action", "--input", "-"}},
		{"action flag and input", `{"summary":"s"}`, []string{"action", "--summary", "s", "--input", "-"}},
	} {
		if _, err := smem(tc.stdin, tc.args...); err == nil {
			t.Errorf("%s: should fail", tc.name)
		}
	}
}
