package smem

import (
	"bytes"
	"encoding/json"
	"testing"
)

// Synced feeds are untrusted input: parsing must never panic.
func FuzzReadEvents(f *testing.F) {
	f.Add([]byte(`{"id":"evt-1","replica":"rep-1","rseq":1,"at":1,"actor":"a","key_id":"k","type":"recall","payload":{},"prev":"0","hash":"h","sig":"s"}` + "\n"))
	f.Add([]byte(`{"id":"evt-trunc","replica":"`))
	f.Add([]byte("\n\n{}\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		evs, _, _ := readEvents(bytes.NewReader(b))
		for _, ev := range evs {
			_ = orderSensitive(ev)
			_ = propagationRoot(ev)
		}
	})
}

// Redaction runs on every payload before it is signed: it must always give
// back valid JSON and never leave a planted value behind.
func FuzzRedactPayload(f *testing.F) {
	f.Add("plain text", "sk-ant-api03-abcdefghijklmnopqrstuvwxyz")
	f.Add(`quote " and backslash \ and API_KEY=`, "hunter2hunter2")
	f.Add("-----BEGIN RSA PRIVATE KEY-----", "x")
	r := DefaultRedactor()
	f.Fuzz(func(t *testing.T, text, secret string) {
		b, err := r.payload(map[string]any{"content": text, "nested": []any{text, map[string]any{"k": text}}})
		if err != nil {
			t.Fatalf("payload: %v", err)
		}
		if !json.Valid(b) {
			t.Fatalf("invalid JSON after redaction: %q", b)
		}
		// Idempotent: redacting the output again changes nothing.
		var v any
		if err := json.Unmarshal(b, &v); err != nil {
			t.Fatal(err)
		}
		again, err := r.payload(v)
		if err != nil || !bytes.Equal(again, b) {
			t.Fatalf("redaction is not idempotent:\n%s\n%s", b, again)
		}
	})
}

func FuzzGlobMatch(f *testing.F) {
	f.Add("**/.env", "a/b/.env")
	f.Add("docs/*.md", "docs/x.md")
	f.Add("[", "x")
	f.Fuzz(func(t *testing.T, pattern, path string) {
		_ = globMatch(pattern, path)
		if !globMatch("**", path) {
			t.Fatalf("** must match %q", path)
		}
	})
}

func FuzzSimilarity(f *testing.F) {
	f.Add("Run make test before committing", "Before committing, run make test")
	f.Fuzz(func(t *testing.T, a, b string) {
		s := similarity(a, b)
		if s < 0 || s > 1 || s != similarity(b, a) {
			t.Fatalf("similarity(%q, %q) = %v", a, b, s)
		}
	})
}
