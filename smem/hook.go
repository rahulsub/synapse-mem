package smem

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// HookInput is the JSON Claude Code sends to hooks on stdin.
type HookInput struct {
	SessionID      string          `json:"session_id"`
	TranscriptPath string          `json:"transcript_path"`
	Cwd            string          `json:"cwd"`
	HookEventName  string          `json:"hook_event_name"`
	Source         string          `json:"source"`     // SessionStart: startup, resume, clear or compact
	AgentID        string          `json:"agent_id"`   // set for tool calls made by a subagent
	AgentType      string          `json:"agent_type"` // the subagent's type
	ToolName       string          `json:"tool_name"`
	ToolInput      json.RawMessage `json:"tool_input"`
	ToolResponse   json.RawMessage `json:"tool_response"`
}

// readOnlyTools are skipped by default: they change nothing, and recording
// every read would swamp the log.
var readOnlyTools = map[string]bool{
	"Read": true, "Glob": true, "Grep": true, "LS": true, "WebSearch": true, "WebFetch": true,
	"TodoWrite": true, "ToolSearch": true, "NotebookRead": true,
}

var commitLine = regexp.MustCompile(`\[[^\]\s]+(?: \([^)]*\))? ([0-9a-f]{7,40})\]`)

// spoolNow is the hook's clock; tests replace it.
var spoolNow = time.Now

// spooled is a tool call captured by the hook, waiting to be recorded.
type spooled struct {
	Actor      string `json:"actor"`
	Session    string `json:"session"`
	Agent      string `json:"agent,omitempty"`
	ObservedAt int64  `json:"observed_at"`
	Tool       string `json:"tool"`
	Summary    string `json:"summary"`
	Commit     string `json:"commit,omitempty"`
	ArgsHash   string `json:"args_hash"`
	ResultHash string `json:"result_hash"`
	Transcript string `json:"transcript,omitempty"`
}

// skipTool reports whether a tool call is not recorded: read-only tools
// (unless includeReadOnly), smem's own MCP tools (they record themselves),
// and hooks.skip_tools.
func skipTool(name string, pol HooksPolicy, includeReadOnly bool) bool {
	if name == "" || strings.Contains(name, "smem__") || (!includeReadOnly && readOnlyTools[name]) {
		return true
	}
	for _, g := range pol.SkipTools {
		if globMatch(g, name) {
			return true
		}
	}
	return false
}

func capture(in HookInput, actor string, now time.Time, r *Redactor) spooled {
	return spooled{Actor: actor, Session: in.SessionID, Agent: in.AgentID, ObservedAt: ms(now), Tool: in.ToolName,
		Summary: r.Redact(summarizeTool(in.ToolInput)), Commit: commitFrom(in.ToolName, in.ToolInput, in.ToolResponse),
		ArgsHash: hashRaw(in.ToolInput), ResultHash: hashRaw(in.ToolResponse), Transcript: in.TranscriptPath}
}

// SpoolToolUse captures a PostToolUse call into the store's spool without
// touching the database, so the hook never waits on the write lock. The
// summary is redacted before it reaches the disk. The next process that
// writes to the store records it (DrainSpool).
func SpoolToolUse(dbPath string, in HookInput, cfg *Config, includeReadOnly bool) error {
	if skipTool(in.ToolName, cfg.Hooks, includeReadOnly) {
		return nil
	}
	r, err := NewRedactor(cfg.Redaction)
	if err != nil {
		return err
	}
	actor := cmp(os.Getenv("SMEM_ACTOR"), cmp(cfg.Actor, defaultActor("claude-code")))
	b, err := json.Marshal(capture(in, actor, spoolNow(), r))
	if err != nil {
		return err
	}
	dir := filepath.Join(filepath.Dir(dbPath), "spool")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// Write then rename: a reader sees a whole record or nothing.
	rnd := make([]byte, 4)
	rand.Read(rnd)
	name := fmt.Sprintf("%019d-%d-%s", time.Now().UnixNano(), os.Getpid(), hex.EncodeToString(rnd))
	tmp := filepath.Join(dir, name+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil { //nolint:gosec // dir is the store's spool; name is generated here
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, name+".json"))
}

// DrainSpool records spooled tool calls, oldest first, in one transaction.
// A file is marked done in the same transaction that records it, so a crash
// before the file is removed can't record it twice.
func (e *Engine) DrainSpool() (int, error) {
	dir := filepath.Join(filepath.Dir(e.path), "spool")
	names, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil || len(names) == 0 {
		return 0, err
	}
	sort.Strings(names)
	var done []string
	n := 0
	actor, session := e.Actor, e.Session
	defer func() { e.Actor, e.Session = actor, session }()
	_, err = e.write(func(w *wtx) error {
		for _, path := range names {
			base := filepath.Base(path)
			var seen int
			if err := w.tx.QueryRow(`SELECT COUNT(*) FROM spool_seen WHERE file = ?`, base).Scan(&seen); err != nil {
				return err
			}
			done = append(done, path)
			if seen > 0 {
				continue
			}
			b, err := os.ReadFile(path) //nolint:gosec // from a glob of the store's own spool directory
			if err != nil {
				return err
			}
			var s spooled
			if json.Unmarshal(b, &s) != nil {
				continue // unreadable: drop it rather than block the spool
			}
			w.e.Actor, w.e.Session = cmp(s.Actor, actor), s.Session
			dec, how, err := w.linkDecision(s.Session, s.ObservedAt)
			if err != nil {
				return err
			}
			p := actionPayload{ID: newID("act"), Decision: dec, LinkedBy: how, Tool: s.Tool, Summary: s.Summary,
				ArgsHash: s.ArgsHash, ResultHash: s.ResultHash, Commit: s.Commit, Transcript: s.Transcript,
				Agent: s.Agent, ObservedAt: s.ObservedAt}
			if _, err := w.emit(evActionRecorded, p.ID, p); err != nil {
				return err
			}
			if _, err := w.tx.Exec(`INSERT INTO spool_seen (file) VALUES (?)`, base); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	for _, p := range done {
		if err := os.Remove(p); err == nil || errors.Is(err, os.ErrNotExist) {
			_, _ = e.db.Exec(`DELETE FROM spool_seen WHERE file = ?`, filepath.Base(p)) // a stale marker only costs a lookup
		}
	}
	return n, nil
}

// SpoolBacklog counts tool calls waiting in the spool.
func (e *Engine) SpoolBacklog() int {
	names, _ := filepath.Glob(filepath.Join(filepath.Dir(e.path), "spool", "*.json"))
	return len(names)
}

// RecordToolUse records a PostToolUse hook call as an action directly,
// without the spool.
func (e *Engine) RecordToolUse(in HookInput, includeReadOnly bool) (string, error) {
	if skipTool(in.ToolName, e.Policy.Hooks, includeReadOnly) {
		return "", nil
	}
	if in.SessionID != "" {
		e.Session = in.SessionID
	}
	s := capture(in, e.Actor, e.Now(), e.redactor)
	p := actionPayload{ID: newID("act"), Tool: s.Tool, Summary: s.Summary, ArgsHash: s.ArgsHash,
		ResultHash: s.ResultHash, Commit: s.Commit, Transcript: s.Transcript, Agent: s.Agent, ObservedAt: s.ObservedAt}
	_, err := e.write(func(w *wtx) error {
		var err error
		if p.Decision, p.LinkedBy, err = w.linkDecision(e.Session, s.ObservedAt); err != nil {
			return err
		}
		_, err = w.emit(evActionRecorded, p.ID, p)
		return err
	})
	return p.ID, err
}

// linkDecision picks the decision a tool call carries out, by
// hooks.link_decisions. This is inference from timing, so it is recorded
// as such ("linked_by"); a Decision: trailer or an explicit action is exact.
func (w *wtx) linkDecision(session string, at int64) (string, string, error) {
	pol := w.e.Policy.Hooks
	if session == "" || pol.LinkDecisions == "never" {
		return "", "", nil
	}
	// Event times run a little ahead of the wall clock (see emitWith), so a
	// decision logged just before the call can carry a slightly later time.
	q := `SELECT id FROM decisions WHERE session = ? AND status = 'active' AND decided_at <= ?`
	args := []any{session, at + 1000}
	if pol.LinkDecisions != "latest" {
		q += ` AND decided_at >= ?`
		args = append(args, at-pol.LinkWindow.D().Milliseconds())
	}
	ids, err := selectAll(w.tx, func(s scanner) (string, error) {
		var id string
		return id, s.Scan(&id)
	}, q+` ORDER BY decided_at DESC LIMIT 2`, args...)
	if err != nil || len(ids) == 0 {
		return "", "", err
	}
	if pol.LinkDecisions == "latest" {
		return ids[0], "latest", nil
	}
	if len(ids) > 1 {
		return "", "", nil // parallel work in one session: don't guess
	}
	return ids[0], "unambiguous", nil
}

func summarizeTool(input json.RawMessage) string {
	var m map[string]any
	if json.Unmarshal(input, &m) == nil {
		for _, k := range []string{"command", "file_path", "notebook_path", "url", "pattern", "description", "prompt"} {
			if s, ok := m[k].(string); ok && s != "" {
				return oneLine(s, 240)
			}
		}
	}
	return oneLine(string(input), 240)
}

// commitFrom finds the sha in `git commit` output, e.g. "[main 1a2b3c4] msg",
// from any agent's shell tool. Only stdout or output is searched, plus Bash's
// raw response: a file write that mentions git commit can echo lookalike text.
func commitFrom(tool string, input, response json.RawMessage) string {
	if !strings.Contains(string(input), "git commit") {
		return ""
	}
	var text string
	var r struct {
		Stdout string `json:"stdout"`
		Output string `json:"output"`
	}
	if json.Unmarshal(response, &r) == nil {
		text = r.Stdout
		if text == "" {
			text = r.Output
		}
	}
	if text == "" && tool == "Bash" {
		text = string(response)
	}
	if m := commitLine.FindStringSubmatch(text); m != nil {
		return m[1]
	}
	return ""
}

func hashRaw(b json.RawMessage) string {
	if len(b) == 0 {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Sessions are tied to processes. Claude Code doesn't tell an MCP server
// which session it serves, but the server and the hooks share an ancestor:
// the Claude Code process. The session-start hook records its session id
// under each of its ancestors' pids; the MCP server looks up its own
// ancestors, nearest first. Two sessions in one directory each find their
// own, and a subagent's calls stay in its parent's session.

func sessionsDir(db string) string { return filepath.Join(filepath.Dir(db), "sessions") }

// SetCurrentSession records id as the session of this process's ancestors.
func (e *Engine) SetCurrentSession(id string) error {
	e.Session = id
	dir := sessionsDir(e.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	pruneSessions(dir)
	for _, pid := range Ancestors() {
		if err := os.WriteFile(filepath.Join(dir, strconv.Itoa(pid)), []byte(id+"\n"), 0o600); err != nil {
			return err
		}
	}
	return nil
}

// CurrentSession returns the session recorded for the nearest ancestor of
// this process, or "".
func (e *Engine) CurrentSession() string { return e.SessionFor(Ancestors()) }

// SessionFor returns the session recorded for the first of pids that has one.
func (e *Engine) SessionFor(pids []int) string {
	for _, pid := range pids {
		if b, err := os.ReadFile(filepath.Join(sessionsDir(e.path), strconv.Itoa(pid))); err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	return ""
}

// pruneSessions removes records for processes that have exited.
func pruneSessions(dir string) {
	ents, _ := os.ReadDir(dir)
	for _, ent := range ents {
		if pid, err := strconv.Atoi(ent.Name()); err == nil && !alive(pid) {
			_ = os.Remove(filepath.Join(dir, ent.Name())) // best-effort cleanup
		}
	}
}

func alive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = p.Signal(syscall.Signal(0))
	return err == nil || errors.Is(err, os.ErrPermission)
}

// Ancestors returns this process's ancestors, nearest first, stopping
// before init.
func Ancestors() []int {
	var out []int
	pid := os.Getppid()
	for i := 0; i < 8 && pid > 1; i++ {
		out = append(out, pid)
		pid = parentOf(pid)
	}
	return out
}

func parentOf(pid int) int {
	if runtime.GOOS == "linux" {
		b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			return 0
		}
		// pid (comm) state ppid ...; comm may contain spaces.
		f := strings.Fields(string(b[strings.LastIndexByte(string(b), ')')+1:]))
		if len(f) < 2 {
			return 0
		}
		ppid, _ := strconv.Atoi(f[1])
		return ppid
	}
	out, err := exec.Command("ps", "-o", "ppid=", "-p", strconv.Itoa(pid)).Output() //nolint:gosec,noctx // fixed program; pid is an integer
	if err != nil {
		return 0
	}
	ppid, _ := strconv.Atoi(strings.TrimSpace(string(out)))
	return ppid
}
