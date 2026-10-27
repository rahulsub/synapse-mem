// Package mcp serves an smem store to agents over the Model Context Protocol
// (JSON-RPC 2.0, one message per line on stdio).
//
// Most requests are handled in order on one database handle. Slow tools (a
// fact-check waits on remote judges) run in the background on a second
// handle, so they never hold up recall or remember.
package mcp

import (
	"bufio"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rahulsub/synapse-mem/smem"
)

// protocolVersions are the MCP revisions this server speaks, newest first.
var protocolVersions = []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}

const instructions = `smem is your long-term memory and decision log for this project.
- Start of a task: memory_recall what you know about it.
- Learned something durable (a fact about the system, a user preference, a procedure that worked): memory_remember it. Not transient chatter.
- A remembered fact turned out wrong: memory_update it if it changed, memory_invalidate it if it no longer holds.
- Made a non-obvious choice: decision_record it with the options you rejected, your assumptions, and the memory ids you relied on. Report how it went with decision_outcome.
- Asked why something is the way it is: why.
- Something failed (test, build, a correction from a person): failure_record it with a consistent label.
- Want a standing rule? rule_propose it with its reason. Never write rules into CLAUDE.md yourself.`

// Server serves one store.
type Server struct {
	Engine  *smem.Engine
	Version string
	// Session, if set, overrides the session the store's hook recorded.
	Session string
	// ActorFromClient signs as the connecting client (e.g. claude-code@host)
	// instead of Engine.Actor.
	ActorFromClient bool

	ancestors []int
	out       sync.Mutex   // serializes responses
	slow      sync.Mutex   // one background call at a time
	bg        *smem.Engine // the background handle, created on first use
	wg        sync.WaitGroup
}

var unsafeActor = regexp.MustCompile(`[^a-z0-9._-]+`)

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Serve reads requests from in and writes responses to out until in ends.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	s.ancestors = smem.Ancestors()
	defer func() {
		s.wg.Wait()
		if s.bg != nil {
			_ = s.bg.Close()
		}
	}()
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	enc := json.NewEncoder(out)
	send := func(r response) error {
		s.out.Lock()
		defer s.out.Unlock()
		return enc.Encode(r)
	}
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			if err := send(response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{-32700, "parse error"}}); err != nil {
				return err
			}
			continue
		}
		if len(req.ID) == 0 {
			continue // a notification: nothing to answer
		}
		if t, args, ok := s.slowCall(req); ok {
			s.syncSession()
			session, actor := s.Engine.Session, s.Engine.Actor
			if s.bg == nil { // cloned here, on the loop that owns s.Engine
				bg, err := s.Engine.Clone()
				if err != nil {
					_ = send(response{JSONRPC: "2.0", ID: req.ID, Result: textResult(err.Error(), true)}) // a dead pipe ends Serve on the next read
					continue
				}
				s.bg = bg
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				result, rerr := s.runSlow(ctx, t, args, session, actor)
				_ = send(response{JSONRPC: "2.0", ID: req.ID, Result: result, Error: rerr}) // as above
			}()
			continue
		}
		result, rerr := s.handle(ctx, req)
		if err := send(response{JSONRPC: "2.0", ID: req.ID, Result: result, Error: rerr}); err != nil {
			return err
		}
	}
	return sc.Err()
}

// slowCall reports whether req calls a slow tool, to run in the background.
func (s *Server) slowCall(req request) (tool, json.RawMessage, bool) {
	if req.Method != "tools/call" {
		return tool{}, nil, false
	}
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if json.Unmarshal(req.Params, &p) != nil {
		return tool{}, nil, false
	}
	t, ok := s.lookup(p.Name)
	if !ok || !t.slow {
		return tool{}, nil, false
	}
	if len(p.Arguments) == 0 {
		p.Arguments = json.RawMessage("{}")
	}
	return t, p.Arguments, true
}

// runSlow runs a slow tool on the background handle, a clone of the main
// one taken with the current session and actor.
func (s *Server) runSlow(ctx context.Context, t tool, args json.RawMessage, session, actor string) (any, *rpcError) {
	s.slow.Lock()
	defer s.slow.Unlock()
	s.bg.Session, s.bg.Actor = session, actor
	return s.result(t.call(ctx, s.bg, args))
}

// lookup finds an enabled tool by name.
func (s *Server) lookup(name string) (tool, bool) {
	if slices.Contains(s.Engine.Policy.MCP.Disable, name) {
		return tool{}, false
	}
	i := slices.IndexFunc(tools, func(t tool) bool { return t.name == name })
	if i < 0 {
		return tool{}, false
	}
	return tools[i], true
}

func (s *Server) result(out any, err error) (any, *rpcError) {
	// Tool failures go back to the model as results it can act on, not as
	// protocol errors.
	if err != nil {
		return textResult(err.Error(), true), nil
	}
	if p, ok := out.(plain); ok {
		return textResult(string(p), false), nil
	}
	b, err := json.MarshalIndent(out, "", " ")
	if err != nil {
		return textResult(err.Error(), true), nil
	}
	return textResult(string(b), false), nil
}

func (s *Server) handle(ctx context.Context, req request) (any, *rpcError) {
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
			ClientInfo      struct {
				Name string `json:"name"`
			} `json:"clientInfo"`
		}
		_ = json.Unmarshal(req.Params, &p) // missing or odd params: use the defaults
		if name := strings.Trim(unsafeActor.ReplaceAllString(strings.ToLower(p.ClientInfo.Name), "-"), "-."); s.ActorFromClient && name != "" {
			s.Engine.Actor = smem.DefaultActorFor(name)
		}
		v := protocolVersions[0]
		if slices.Contains(protocolVersions, p.ProtocolVersion) {
			v = p.ProtocolVersion
		}
		return map[string]any{
			"protocolVersion": v,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "smem", "version": s.Version},
			"instructions":    cmp.Or(s.Engine.Policy.MCP.Instructions, instructions),
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		list := []map[string]any{}
		for _, t := range tools {
			if _, ok := s.lookup(t.name); ok {
				list = append(list, map[string]any{"name": t.name, "description": t.desc, "inputSchema": t.schema})
			}
		}
		return map[string]any{"tools": list}, nil
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return nil, &rpcError{-32602, "invalid params"}
		}
		t, ok := s.lookup(p.Name)
		if !ok {
			return nil, &rpcError{-32602, "unknown tool " + p.Name}
		}
		if len(p.Arguments) == 0 {
			p.Arguments = json.RawMessage("{}")
		}
		s.syncSession()
		if _, err := s.Engine.DrainSpool(); err != nil {
			fmt.Fprintln(os.Stderr, "smem mcp: spool:", err)
		}
		return s.result(t.call(ctx, s.Engine, p.Arguments))
	}
	return nil, &rpcError{-32601, "method not found: " + req.Method}
}

// syncSession files work under the session of the Claude Code process this
// server belongs to (recorded by the session-start hook), so recalls,
// decisions and the hook's tool calls line up. It runs on the main loop
// only; background calls get a copy of the session when dispatched.
func (s *Server) syncSession() {
	switch {
	case s.Session != "":
		s.Engine.Session = s.Session
	case os.Getenv("SMEM_SESSION") != "":
	default:
		if id := s.Engine.SessionFor(s.ancestors); id != "" {
			s.Engine.Session = id
		}
	}
}

var zeroTime time.Time

func round(x float64) float64 { return math.Round(x*1000) / 1000 }

func textResult(text string, isError bool) map[string]any {
	return map[string]any{"content": []map[string]any{{"type": "text", "text": text}}, "isError": isError}
}

// tool is one MCP tool. call decodes its own arguments. A slow tool runs
// in the background.
type tool struct {
	name   string
	desc   string
	schema map[string]any
	call   func(context.Context, *smem.Engine, json.RawMessage) (any, error)
	slow   bool
}

// handler adapts a typed function to a tool call.
func handler[A any](fn func(context.Context, *smem.Engine, A) (any, error)) func(context.Context, *smem.Engine, json.RawMessage) (any, error) {
	return func(ctx context.Context, e *smem.Engine, raw json.RawMessage) (any, error) {
		var a A
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, fmt.Errorf("arguments: %w", err)
		}
		return fn(ctx, e, a)
	}
}

func required(fields map[string]string) error {
	for name, v := range fields {
		if v == "" {
			return errors.New(name + " is required")
		}
	}
	return nil
}
