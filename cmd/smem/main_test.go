package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
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

func TestRecallJSONIsRepeatable(t *testing.T) {
	t.Setenv("SMEM_DB", filepath.Join(t.TempDir(), "smem.db"))
	t.Setenv("SMEM_CONFIG", filepath.Join(t.TempDir(), "none.json"))
	t.Setenv("SMEM_KEY_DIR", filepath.Join(t.TempDir(), "keys"))
	t.Setenv("SMEM_ACTOR", "tester")
	var out bytes.Buffer
	for _, c := range []string{"Staging outages do not page anyone", "Office espresso machine outages go to facilities", "The cafeteria menu changes weekly"} {
		if err := run([]string{"remember", "--kind", "fact", c}, strings.NewReader(""), &out); err != nil {
			t.Fatal(err)
		}
	}
	recall := func() string {
		var o bytes.Buffer
		if err := run([]string{"recall", "--no-record", "--json", "staging database outages"}, strings.NewReader(""), &o); err != nil {
			t.Fatal(err)
		}
		var hits []struct {
			ID        string
			Relevance float64
		}
		if err := json.Unmarshal(o.Bytes(), &hits); err != nil || len(hits) != 2 {
			t.Fatalf("recall output (%v): %s", err, o.String())
		}
		sort.Slice(hits, func(i, j int) bool { return hits[i].ID < hits[j].ID })
		return fmt.Sprint(hits)
	}
	if a, b := recall(), recall(); a != b {
		t.Fatalf("two recalls differ:\n%s\n%s", a, b)
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
