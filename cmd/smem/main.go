// Command smem is the CLI for the smem agent memory.
package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rahulsub/synapse-mem/mcp"
	"github.com/rahulsub/synapse-mem/smem"
)

const usage = `smem: agent memory with decay, decision provenance and a signed audit log

Usage: smem [--db path] [--actor name] [--session id] <command> [args]

Memory
  remember <content>       --kind fact|episode|procedure|preference|insight --scope --volatility
                           --confidence --valid-from --from id,...
  supersede <mem> <content> new version of a memory (flags as remember)
  invalidate <mem>         it stopped being true   --reason --valid-to
  retract <mem>            it was never true       --reason
  reconfirm <mem>          checked, still true     --confidence --note
  signal <mem> used|confirmed|contradicted  --note
  recall [query]           --kind --scope --limit --as-of --known-at --archived --no-record --explain --json
  context                  memories for session start   --budget
  sweep                    archive faded memories   --threshold --idle --dry-run

Decisions and work
  decide                   --question --choice --why --reject "opt|reason" --assume "stmt|check"
                           --used mem,... --evidence ref,... --context mem,... --bead --supersedes --model --prompt-hash
  outcome <dec> success|failure|mixed  --note
  approve <dec>            --by --scope --note
  reaffirm <dec>           --note
  revert <dec>             --reason
  assumptions              --status open|held|broken
  assumption break|hold <asm>  --reason
  action                   --tool --summary --decision --bead --commit
  source <ref>             --kind --hash --note
  trailer <dec>            print the commit trailer for a decision

Audit
  why <ref>                decision, memory, assumption, source, action, commit sha or bead id   --json
  review                   suspect, at-risk and conflicting records; untrusted keys   --json
  log                      --subject --type --limit --json
  verify                   check every hash, chain link and signature   --json
  heads                    latest hash per replica (publish these to anchor the log)
  rebuild                  drop and replay all projections

Keys and sync
  keys                     list signing keys
  keys trust|distrust <key-id>
  remote add <name> <dir>  --pull-only (read-only source) | remote list
  sync [remote]            pull then push
  push [remote] | pull [remote]
  export [--replica id]    events as JSON lines on stdout
  import <file|->          verify and merge events

Rules (admitted only with a reason; see docs/CONFIG.md "rules")
  failure <label> <summary> record a failure   --ref
  failures                 --label --limit
  rules [list]             --status proposed|active|suspect|retired|rejected (default active) --json
  rules propose <text>     --why requested|incident|decision --by --quote --transcript --decision
                           --label --failures fail,... --enforced-by --scope
  rules approve <rule>     a person admits a held proposal   --by --note
  rules reject|retire|reaffirm|violated <rule>...   --reason
  rules merge <rule> <rule>... --text   replace several rules with one
  rules rationalize        duplicates, held, promotable, ineffective, violated, stale, over cap
                           --import file,... (CLAUDE.md, .claude/rules/*.md) --judges --json
  rules render             write active rules into a managed block   --file (default rules.file) --check

Fact-checking
  factcheck [mem...]       user checkers first, then judges (Jev, then Claude if unsure)
                           --due --threshold --limit --parallel --dry-run --json
  judges                   which judges and checkers are configured   --ping

Setup
  init                     create .smem/smem.db here   --claude-code (also write .mcp.json and hooks) --bin
  doctor                   check the setup: store, keys, config, judges, trust, spool, remotes   --ping --json
  stats                    what the store holds and how fast the log grows   --json
  mcp                      serve this store to an agent over MCP (stdio)   --init --session
  version                  print the version
  hook post-tool-use       record a Claude Code tool call (reads hook JSON on stdin)  --all
  hook session-start       print context for a Claude Code SessionStart hook  --budget
`

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "smem:", err)
		os.Exit(1)
	}
}

type cli struct {
	e   *smem.Engine
	in  io.Reader
	out io.Writer
	cfg *smem.Config
	// actorSet is true when the actor was chosen explicitly (flag, config
	// or SMEM_ACTOR) rather than defaulted.
	actorSet bool
}

func run(args []string, stdin io.Reader, stdout io.Writer) error {
	global := flag.NewFlagSet("smem", flag.ContinueOnError)
	global.Usage = func() { fmt.Fprint(stdout, usage) }
	dbPath := global.String("db", "", "database path (default: nearest .smem/smem.db, or $SMEM_DB)")
	actor := global.String("actor", "", "actor name (default: $SMEM_ACTOR or $USER)")
	session := global.String("session", "", "session id (default: $SMEM_SESSION)")
	if err := global.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if global.NArg() == 0 {
		fmt.Fprint(stdout, usage)
		return nil
	}
	cmd, rest := global.Arg(0), global.Args()[1:]
	switch cmd {
	case "help":
		fmt.Fprint(stdout, usage)
		return nil
	case "version":
		fmt.Fprintf(stdout, "smem %s\n", version)
		return nil
	}

	if cmd == "hook" {
		return runHook(*dbPath, *actor, rest, stdin, stdout)
	}
	fn, ok := commands[cmd]
	if !ok {
		return fmt.Errorf("unknown command %q (see `smem help`)", cmd)
	}
	path := findDB(*dbPath, "")
	switch {
	case cmd == "init", cmd == "mcp" && path == "" && slices.Contains(rest, "--init"):
		if path == "" || *dbPath == "" {
			path = filepath.Join(".smem", "smem.db")
		}
	case path == "" && cmd == "doctor":
		return (&cli{in: stdin, out: stdout}).doctor(rest)
	case path == "":
		return errors.New("no smem database found here or in any parent directory; run `smem init`, pass --db or set SMEM_DB")
	}
	cfg, err := smem.LoadConfigFor(path)
	if err != nil {
		return err
	}
	e, err := smem.Open(path)
	if err != nil {
		return err
	}
	defer e.Close() //nolint:errcheck // the process exits next
	if err := e.Configure(cfg); err != nil {
		return err
	}
	if *actor != "" {
		e.Actor = *actor
	}
	if *session != "" {
		e.Session = *session
	}
	if _, err := e.DrainSpool(); err != nil {
		fmt.Fprintln(os.Stderr, "smem: recording spooled tool calls:", err)
	}
	c := &cli{e: e, in: stdin, out: stdout, cfg: cfg, actorSet: *actor != "" || cfg.Actor != "" || os.Getenv("SMEM_ACTOR") != ""}
	return fn(c, rest)
}

// runHook runs a Claude Code hook. Hooks read their input first, so the
// store is found from the session's working directory (not wherever the
// hook process happens to start), and they never fail the agent unless
// hooks.require_store says a missing store is an error.
func runHook(dbFlag, actorFlag string, args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("hook", flag.ContinueOnError)
	all := fs.Bool("all", false, "also record read-only tools")
	budget := fs.Int("budget", 0, "context budget (session-start; default context.budget)")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if err := need(pos, 1, "smem hook post-tool-use|session-start"); err != nil {
		return err
	}
	var in smem.HookInput
	if b, _ := io.ReadAll(stdin); len(b) > 0 {
		if err := json.Unmarshal(b, &in); err != nil {
			fmt.Fprintln(os.Stderr, "smem hook: input:", err)
			return nil
		}
	}
	path := findDB(dbFlag, in.Cwd)
	if path == "" {
		local, _ := smem.LoadConfig(smem.LocalConfigPath())
		if local != nil && local.Hooks.RequireStore {
			return fmt.Errorf("no smem store for %s (hooks.require_store is set)", cmp.Or(in.Cwd, "the working directory"))
		}
		return nil
	}
	if err := hook(path, actorFlag, pos[0], in, *all, *budget, stdout); err != nil {
		fmt.Fprintln(os.Stderr, "smem hook:", err)
	}
	return nil
}

func hook(path, actorFlag, event string, in smem.HookInput, all bool, budget int, stdout io.Writer) error {
	cfg, err := smem.LoadConfigFor(path)
	if err != nil {
		return err
	}
	if event == "post-tool-use" && cfg.Hooks.Spool {
		return smem.SpoolToolUse(path, in, cfg, all)
	}
	e, err := smem.OpenWith(path, smem.OpenOptions{BusyTimeout: cfg.Hooks.LockTimeout.D()})
	if err != nil {
		return err
	}
	defer e.Close() //nolint:errcheck // the process exits next
	if err := e.Configure(cfg); err != nil {
		return err
	}
	if actorFlag != "" {
		e.Actor = actorFlag
	} else if os.Getenv("SMEM_ACTOR") == "" && cfg.Actor == "" {
		e.Actor = smem.DefaultActorFor("claude-code")
	}
	switch event {
	case "post-tool-use":
		_, err := e.RecordToolUse(in, all)
		return err
	case "session-start":
		if in.SessionID != "" {
			if err := e.SetCurrentSession(in.SessionID); err != nil {
				return err
			}
		}
		if _, err := e.DrainSpool(); err != nil {
			return err
		}
		if in.Source != "" && !slices.Contains(cfg.Context.On, in.Source) {
			return nil // context.on: nothing to inject for this kind of start
		}
		s, err := e.Context(budget)
		if err != nil {
			return err
		}
		fmt.Fprint(stdout, s)
		return nil
	}
	return fmt.Errorf("unknown hook %q", event)
}

// findDB finds the store: an explicit path, $SMEM_DB, or the nearest
// .smem/smem.db at or above start (default: the working directory).
func findDB(explicit, start string) string {
	if explicit != "" {
		return explicit
	}
	if p := os.Getenv("SMEM_DB"); p != "" {
		return p
	}
	dir := start
	if dir == "" {
		var err error
		if dir, err = os.Getwd(); err != nil {
			return ""
		}
	}
	for {
		p := filepath.Join(dir, ".smem", "smem.db")
		if _, err := os.Stat(p); err == nil {
			return p
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

var commands = map[string]func(*cli, []string) error{
	"init": (*cli).initCmd, "remember": (*cli).remember, "supersede": (*cli).supersede,
	"invalidate": (*cli).invalidate, "retract": (*cli).retract, "reconfirm": (*cli).reconfirm,
	"signal": (*cli).signal, "recall": (*cli).recall, "context": (*cli).context, "sweep": (*cli).sweep,
	"decide": (*cli).decide, "outcome": (*cli).outcome, "approve": (*cli).approve, "reaffirm": (*cli).reaffirm,
	"revert": (*cli).revert, "assumptions": (*cli).assumptions, "assumption": (*cli).assumption,
	"action": (*cli).action, "source": (*cli).source, "trailer": (*cli).trailer,
	"why": (*cli).why, "review": (*cli).review, "log": (*cli).log, "verify": (*cli).verify,
	"heads": (*cli).heads, "rebuild": (*cli).rebuild, "keys": (*cli).keys, "remote": (*cli).remote,
	"sync": (*cli).sync, "push": (*cli).push, "pull": (*cli).pull, "export": (*cli).export,
	"import": (*cli).importCmd, "hook": nil,
	"factcheck": (*cli).factcheck, "judges": (*cli).judges, "mcp": (*cli).mcp,
	"doctor": (*cli).doctor, "stats": (*cli).stats, "failure": (*cli).failure, "failures": (*cli).failuresCmd,
	"rules": (*cli).rules,
}

// parse parses flags that may appear before, between or after positional args.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	fs.SetOutput(io.Discard)
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func need(pos []string, n int, what string) error {
	if len(pos) < n {
		return fmt.Errorf("usage: %s", what)
	}
	return nil
}

type list []string

func (l *list) String() string { return strings.Join(*l, ",") }
func (l *list) Set(v string) error {
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			*l = append(*l, p)
		}
	}
	return nil
}

// multi collects a repeatable flag without splitting on commas.
type multi []string

func (m *multi) String() string     { return strings.Join(*m, "; ") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

var relTime = regexp.MustCompile(`^-(\d+)([smhdw])$`)

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	if s == "now" {
		return time.Now(), nil
	}
	if m := relTime.FindStringSubmatch(s); m != nil {
		n, _ := strconv.Atoi(m[1])
		unit := map[string]time.Duration{"s": time.Second, "m": time.Minute, "h": time.Hour, "d": 24 * time.Hour, "w": 7 * 24 * time.Hour}[m[2]]
		return time.Now().Add(-time.Duration(n) * unit), nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04", "2006-01-02 15:04", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("can't parse time %q (use RFC3339, YYYY-MM-DD, or -3d / -12h)", s)
}

func parseDuration(s string) (time.Duration, error) {
	if m := regexp.MustCompile(`^(\d+)([dw])$`).FindStringSubmatch(s); m != nil {
		n, _ := strconv.Atoi(m[1])
		return time.Duration(n) * map[string]time.Duration{"d": 24 * time.Hour, "w": 7 * 24 * time.Hour}[m[2]], nil
	}
	return time.ParseDuration(s)
}

func (c *cli) printf(format string, a ...any) { fmt.Fprintf(c.out, format, a...) }

func (c *cli) json(v any) error {
	enc := json.NewEncoder(c.out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func (c *cli) flags(fl []smem.Flag) {
	for _, f := range fl {
		c.printf("  ⚠ %s is now suspect (because %s changed)\n", f.Subject, f.Cause)
	}
	if len(fl) > 0 {
		c.printf("  run `smem review` to look at them\n")
	}
}

// --- commands ---------------------------------------------------------------

func (c *cli) initCmd(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	claude := fs.Bool("claude-code", false, "also wire Claude Code into this project: .mcp.json and hooks in .claude/settings.json")
	bin := fs.String("bin", "smem", "with --claude-code: the smem command those files run")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	c.printf("smem database: %s\nreplica: %s\nactor: %s (keys in %s)\n", c.e.Path(), c.e.Replica(), c.e.Actor, c.e.KeyDir)
	if !*claude {
		c.printf("\nTo wire up Claude Code in this project (kept with the repo, unlike a plugin install): smem init --claude-code\n")
		return nil
	}
	root := filepath.Dir(filepath.Dir(c.e.Path()))
	changed, err := wireClaudeCode(root, *bin)
	if err != nil {
		return err
	}
	for _, f := range changed {
		c.printf("updated %s\n", f)
	}
	return nil
}

// wireClaudeCode adds the smem MCP server to .mcp.json and the hooks to
// .claude/settings.json, keeping everything else in those files. These live
// in the project, so they survive an agent whose home directory does not.
func wireClaudeCode(root, bin string) ([]string, error) {
	var changed []string
	edit := func(rel string, fn func(map[string]any)) error {
		p := filepath.Join(root, rel)
		m := map[string]any{}
		if b, err := os.ReadFile(p); err == nil { //nolint:gosec // .mcp.json or .claude/settings.json in the project
			if err := json.Unmarshal(b, &m); err != nil {
				return fmt.Errorf("%s: %w", rel, err)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		fn(m)
		b, err := json.MarshalIndent(m, "", "  ")
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil { //nolint:gosec // the project's .claude directory
			return err
		}
		changed = append(changed, rel)
		return os.WriteFile(p, append(b, '\n'), 0o644) //nolint:gosec // project files, committed and shared
	}
	obj := func(m map[string]any, k string) map[string]any {
		v, ok := m[k].(map[string]any)
		if !ok {
			v = map[string]any{}
			m[k] = v
		}
		return v
	}
	if err := edit(".mcp.json", func(m map[string]any) {
		obj(m, "mcpServers")["smem"] = map[string]any{"command": bin, "args": []string{"mcp", "--init"}}
	}); err != nil {
		return nil, err
	}
	err := edit(filepath.Join(".claude", "settings.json"), func(m map[string]any) {
		hooks := obj(m, "hooks")
		for event, sub := range map[string]string{"SessionStart": "session-start", "PostToolUse": "post-tool-use"} {
			cmd := bin + " hook " + sub
			groups, _ := hooks[event].([]any)
			present := false
			for _, g := range groups {
				gm, _ := g.(map[string]any)
				hs, _ := gm["hooks"].([]any)
				for _, h := range hs {
					hm, _ := h.(map[string]any)
					present = present || hm["command"] == cmd
				}
			}
			if !present {
				hooks[event] = append(groups, map[string]any{"matcher": "", "hooks": []any{
					map[string]any{"type": "command", "command": cmd, "timeout": 10}}})
			}
		}
	})
	return changed, err
}

func memoryFlags(fs *flag.FlagSet) (*smem.MemoryInput, func() error) {
	in := &smem.MemoryInput{}
	var validFrom string
	var from list
	fs.StringVar(&in.Kind, "kind", "", "fact|episode|procedure|preference|insight")
	fs.StringVar(&in.Scope, "scope", "", "scope")
	fs.StringVar(&in.Volatility, "volatility", "", "volatile|normal|stable|permanent")
	fs.Float64Var(&in.Confidence, "confidence", 0, "0..1")
	fs.StringVar(&validFrom, "valid-from", "", "when it became true")
	fs.Var(&from, "from", "ids this was derived from")
	return in, func() error {
		t, err := parseTime(validFrom)
		in.ValidFrom, in.DerivedFrom = t, from
		return err
	}
}

func (c *cli) remember(args []string) error {
	fs := flag.NewFlagSet("remember", flag.ContinueOnError)
	in, finish := memoryFlags(fs)
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if err := need(pos, 1, `smem remember "content" [--kind ...]`); err != nil {
		return err
	}
	if err := finish(); err != nil {
		return err
	}
	in.Content = strings.Join(pos, " ")
	id, err := c.e.Remember(*in)
	if err != nil {
		return err
	}
	c.printf("%s\n", id)
	return nil
}

func (c *cli) supersede(args []string) error {
	fs := flag.NewFlagSet("supersede", flag.ContinueOnError)
	in, finish := memoryFlags(fs)
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if err := need(pos, 2, `smem supersede <mem> "new content"`); err != nil {
		return err
	}
	if err := finish(); err != nil {
		return err
	}
	if in.Kind == "" {
		if old, err := c.e.Memory(pos[0]); err == nil {
			in.Kind = old.Kind
			if in.Scope == "" {
				in.Scope = old.Scope
			}
		}
	}
	in.Content = strings.Join(pos[1:], " ")
	id, fl, err := c.e.Supersede(pos[0], *in)
	if err != nil {
		return err
	}
	c.printf("%s supersedes %s\n", id, pos[0])
	c.flags(fl)
	return nil
}

func (c *cli) invalidate(args []string) error {
	fs := flag.NewFlagSet("invalidate", flag.ContinueOnError)
	reason := fs.String("reason", "", "why")
	validTo := fs.String("valid-to", "", "when it stopped being true (default now)")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if err := need(pos, 1, "smem invalidate <mem> --reason ..."); err != nil {
		return err
	}
	t, err := parseTime(*validTo)
	if err != nil {
		return err
	}
	fl, err := c.e.Invalidate(pos[0], *reason, t)
	if err != nil {
		return err
	}
	c.printf("%s invalidated\n", pos[0])
	c.flags(fl)
	return nil
}

func (c *cli) retract(args []string) error {
	fs := flag.NewFlagSet("retract", flag.ContinueOnError)
	reason := fs.String("reason", "", "why")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if err := need(pos, 1, "smem retract <mem> --reason ..."); err != nil {
		return err
	}
	fl, err := c.e.Retract(pos[0], *reason)
	if err != nil {
		return err
	}
	c.printf("%s retracted\n", pos[0])
	c.flags(fl)
	return nil
}

func (c *cli) reconfirm(args []string) error {
	fs := flag.NewFlagSet("reconfirm", flag.ContinueOnError)
	conf := fs.Float64("confidence", 0, "new confidence (default keep)")
	note := fs.String("note", "", "how it was checked")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if err := need(pos, 1, "smem reconfirm <mem>"); err != nil {
		return err
	}
	return c.e.Reconfirm(pos[0], *conf, *note)
}

func (c *cli) signal(args []string) error {
	fs := flag.NewFlagSet("signal", flag.ContinueOnError)
	note := fs.String("note", "", "note")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if err := need(pos, 2, "smem signal <mem> used|confirmed|contradicted"); err != nil {
		return err
	}
	return c.e.Signal(pos[0], pos[1], *note)
}

func (c *cli) recall(args []string) error {
	fs := flag.NewFlagSet("recall", flag.ContinueOnError)
	var kinds list
	fs.Var(&kinds, "kind", "kinds to include")
	scope := fs.String("scope", "", "scope")
	limit := fs.Int("limit", 10, "max results")
	asOf := fs.String("as-of", "", "what was true at this time")
	knownAt := fs.String("known-at", "", "as believed at this time")
	archived := fs.Bool("archived", false, "include archived memories")
	noRecord := fs.Bool("no-record", false, "don't record this recall")
	explain := fs.Bool("explain", false, "show score breakdown")
	asJSON := fs.Bool("json", false, "JSON output")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	q := smem.RecallQuery{Text: strings.Join(pos, " "), Kinds: kinds, Scope: *scope, Limit: *limit,
		IncludeArchived: *archived, NoRecord: *noRecord}
	if q.AsOf, err = parseTime(*asOf); err != nil {
		return err
	}
	if q.KnownAt, err = parseTime(*knownAt); err != nil {
		return err
	}
	hits, err := c.e.Recall(q)
	if err != nil {
		return err
	}
	if *asJSON {
		return c.json(hits)
	}
	if len(hits) == 0 {
		c.printf("(nothing)\n")
	}
	for _, h := range hits {
		mark := ""
		if h.Status != "active" {
			mark = " [" + h.Status + "]"
		}
		c.printf("%s  %.3f  %-10s %s%s\n", h.ID, h.Score, h.Kind, oneLine(h.Content, 100), mark)
		if *explain {
			c.printf("    relevance %.2f × salience %.2f × confidence %.2f   (activation %.2f, %d uses, last %s, %s)\n",
				h.Relevance, h.Salience, h.Confidence, h.Activation, h.Uses, h.LastAccess.Local().Format("2006-01-02"), h.Volatility)
		}
	}
	return nil
}

func (c *cli) context(args []string) error {
	fs := flag.NewFlagSet("context", flag.ContinueOnError)
	budget := fs.Int("budget", 0, "max characters (default context.budget)")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	s, err := c.e.Context(*budget)
	if err != nil {
		return err
	}
	c.printf("%s", s)
	return nil
}

func (c *cli) sweep(args []string) error {
	fs := flag.NewFlagSet("sweep", flag.ContinueOnError)
	threshold := fs.Float64("threshold", 0.15, "archive below this salience")
	idle := fs.String("idle", "30d", "only if untouched this long")
	dry := fs.Bool("dry-run", false, "list without archiving")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	d, err := parseDuration(*idle)
	if err != nil {
		return err
	}
	hits, err := c.e.Sweep(*threshold, d, *dry)
	if err != nil {
		return err
	}
	verb := "archived"
	if *dry {
		verb = "would archive"
	}
	for _, h := range hits {
		c.printf("%s %s (salience %.3f) %s\n", verb, h.ID, h.Salience, oneLine(h.Content, 80))
	}
	c.printf("%d memories %s\n", len(hits), verb)
	return nil
}

func splitPipe(s string) (string, string) {
	a, b, _ := strings.Cut(s, "|")
	return strings.TrimSpace(a), strings.TrimSpace(b)
}

func (c *cli) decide(args []string) error {
	fs := flag.NewFlagSet("decide", flag.ContinueOnError)
	var in smem.DecisionInput
	var rejects, assumes multi
	var used, evidence, ctx, skills list
	fs.StringVar(&in.Question, "question", "", "what was decided")
	fs.StringVar(&in.Choice, "choice", "", "what was chosen")
	fs.StringVar(&in.Rationale, "why", "", "rationale")
	fs.Var(&rejects, "reject", `"option|reason" (repeatable)`)
	fs.Var(&assumes, "assume", `"statement|how to check" (repeatable)`)
	fs.Var(&used, "used", "memories relied on")
	fs.Var(&evidence, "evidence", "ids or references")
	fs.Var(&ctx, "context", "memories in view (default: last recall in session)")
	fs.Var(&skills, "skills", "skills/rules loaded")
	fs.StringVar(&in.Bead, "bead", "", "bead id")
	fs.StringVar(&in.Supersedes, "supersedes", "", "decision this replaces")
	fs.StringVar(&in.Model, "model", "", "model id")
	fs.StringVar(&in.PromptHash, "prompt-hash", "", "hash of the prompt")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	for _, r := range rejects {
		o, why := splitPipe(r)
		in.Rejected = append(in.Rejected, smem.Option{Option: o, Reason: why})
	}
	for _, a := range assumes {
		s, hint := splitPipe(a)
		in.Assumptions = append(in.Assumptions, smem.AssumptionInput{Statement: s, CheckHint: hint})
	}
	in.Used, in.Evidence, in.Context, in.Skills = used, evidence, ctx, skills
	id, fl, err := c.e.Decide(in)
	if err != nil {
		return err
	}
	c.printf("%s\ncommit trailer: Decision: %s\n", id, id)
	c.flags(fl)
	return nil
}

func (c *cli) outcome(args []string) error {
	fs := flag.NewFlagSet("outcome", flag.ContinueOnError)
	note := fs.String("note", "", "note")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if err := need(pos, 2, "smem outcome <dec> success|failure|mixed"); err != nil {
		return err
	}
	return c.e.Outcome(pos[0], pos[1], *note)
}

func (c *cli) approve(args []string) error {
	fs := flag.NewFlagSet("approve", flag.ContinueOnError)
	by := fs.String("by", "", "approver (default: actor)")
	scope := fs.String("scope", "", "what the approval covers")
	note := fs.String("note", "", "note")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if err := need(pos, 1, "smem approve <dec> --by name"); err != nil {
		return err
	}
	if *by == "" {
		*by = c.e.Actor
	}
	return c.e.Approve(pos[0], *by, *scope, *note)
}

func (c *cli) reaffirm(args []string) error {
	fs := flag.NewFlagSet("reaffirm", flag.ContinueOnError)
	note := fs.String("note", "", "why it still stands")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if err := need(pos, 1, "smem reaffirm <dec> --note ..."); err != nil {
		return err
	}
	return c.e.Reaffirm(pos[0], *note)
}

func (c *cli) revert(args []string) error {
	fs := flag.NewFlagSet("revert", flag.ContinueOnError)
	reason := fs.String("reason", "", "why")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if err := need(pos, 1, "smem revert <dec> --reason ..."); err != nil {
		return err
	}
	fl, err := c.e.Revert(pos[0], *reason)
	if err != nil {
		return err
	}
	c.printf("%s reverted\n", pos[0])
	c.flags(fl)
	return nil
}

func (c *cli) assumptions(args []string) error {
	fs := flag.NewFlagSet("assumptions", flag.ContinueOnError)
	st := fs.String("status", "", "open|held|broken")
	asJSON := fs.Bool("json", false, "JSON output")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	as, err := c.e.Assumptions(*st)
	if err != nil {
		return err
	}
	if *asJSON {
		return c.json(as)
	}
	for _, a := range as {
		c.printf("%s [%s] %s  (for %s)\n", a.ID, a.Status, a.Statement, a.DecisionID)
		if a.CheckHint != "" {
			c.printf("    check: %s\n", a.CheckHint)
		}
	}
	return nil
}

func (c *cli) assumption(args []string) error {
	fs := flag.NewFlagSet("assumption", flag.ContinueOnError)
	reason := fs.String("reason", "", "what was found")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if err := need(pos, 2, "smem assumption break|hold <asm> --reason ..."); err != nil {
		return err
	}
	switch pos[0] {
	case "break":
		fl, err := c.e.BreakAssumption(pos[1], *reason)
		if err != nil {
			return err
		}
		c.printf("%s broken\n", pos[1])
		c.flags(fl)
		return nil
	case "hold":
		return c.e.HoldAssumption(pos[1], *reason)
	}
	return errors.New("usage: smem assumption break|hold <asm>")
}

func (c *cli) action(args []string) error {
	fs := flag.NewFlagSet("action", flag.ContinueOnError)
	var in smem.ActionInput
	fs.StringVar(&in.Tool, "tool", "", "tool or kind of work")
	fs.StringVar(&in.Summary, "summary", "", "what was done")
	fs.StringVar(&in.Decision, "decision", "", "decision this carries out")
	fs.StringVar(&in.Bead, "bead", "", "bead id")
	fs.StringVar(&in.Commit, "commit", "", "commit sha")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	id, err := c.e.RecordAction(in)
	if err != nil {
		return err
	}
	c.printf("%s\n", id)
	return nil
}

func (c *cli) source(args []string) error {
	fs := flag.NewFlagSet("source", flag.ContinueOnError)
	kind := fs.String("kind", "", "transcript|doc|commit|url|bead|human|...")
	hash := fs.String("hash", "", "content hash")
	note := fs.String("note", "", "note")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if err := need(pos, 1, "smem source <ref>"); err != nil {
		return err
	}
	id, err := c.e.CaptureSource(*kind, pos[0], *hash, *note)
	if err != nil {
		return err
	}
	c.printf("%s\n", id)
	return nil
}

func (c *cli) trailer(args []string) error {
	if err := need(args, 1, "smem trailer <dec>"); err != nil {
		return err
	}
	if _, err := c.e.Decision(args[0]); err != nil {
		return err
	}
	c.printf("Decision: %s\n", args[0])
	return nil
}

func (c *cli) why(args []string) error {
	fs := flag.NewFlagSet("why", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "JSON output")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if err := need(pos, 1, "smem why <ref>"); err != nil {
		return err
	}
	t, err := c.e.Why(pos[0])
	if err != nil {
		return err
	}
	if *asJSON {
		return c.json(t)
	}
	c.printf("%s", t.Text())
	return nil
}

func (c *cli) review(args []string) error {
	fs := flag.NewFlagSet("review", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "JSON output")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	rv, err := c.e.Review()
	if err != nil {
		return err
	}
	if *asJSON {
		return c.json(rv)
	}
	section := func(title string, items []smem.ReviewItem, line func(smem.ReviewItem)) {
		if len(items) == 0 {
			return
		}
		c.printf("%s\n", title)
		for _, it := range items {
			line(it)
		}
		c.printf("\n")
	}
	section("Suspect: something they relied on changed", rv.Suspect, func(it smem.ReviewItem) {
		c.printf("  %s (%s) %s\n    because %s: %s\n", it.ID, it.Kind, oneLine(it.Summary, 90), it.Cause, it.Reason)
	})
	section("At risk: downstream of a suspect record (not flagged automatically)", rv.AtRisk, func(it smem.ReviewItem) {
		c.printf("  %s (%s) %s\n    via %s\n", it.ID, it.Kind, oneLine(it.Summary, 90), it.Via)
	})
	section("Conflicts: more than one live successor", rv.Conflicts, func(it smem.ReviewItem) {
		c.printf("  %s → %s\n", it.ID, it.Summary)
	})
	if len(rv.Judges) > 0 {
		c.printf("Judges failing (last 24h)\n")
		for _, h := range rv.Judges {
			c.printf("  %s: %d of %d call(s) failed; last: %s\n", h.Judge, h.Failed, h.OK+h.Failed, h.LastError)
		}
		c.printf("\n")
	}
	if len(rv.UntrustedKeys) > 0 {
		c.printf("Untrusted keys (smem keys trust <key-id>)\n")
		for _, k := range rv.UntrustedKeys {
			c.printf("  %s %s (%d events from %s)\n", k.KeyID, k.Actor, k.Events, k.Replica)
		}
		c.printf("\n")
	}
	if len(rv.Suspect)+len(rv.AtRisk)+len(rv.Conflicts)+len(rv.UntrustedKeys)+len(rv.Judges) == 0 {
		c.printf("nothing to review\n")
	} else {
		c.printf("Resolve with: reaffirm/revert <dec>, reconfirm/invalidate <mem>, supersede to pick a version.\n")
	}
	return nil
}

func (c *cli) log(args []string) error {
	fs := flag.NewFlagSet("log", flag.ContinueOnError)
	subject := fs.String("subject", "", "record id")
	typ := fs.String("type", "", "event type")
	limit := fs.Int("limit", 30, "max events")
	asJSON := fs.Bool("json", false, "JSON output")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	evs, err := c.e.Events(*subject, *typ, *limit)
	if err != nil {
		return err
	}
	if *asJSON {
		return c.json(evs)
	}
	for _, ev := range evs {
		c.printf("%s  %s\n", ev.String(), oneLine(string(ev.Payload), 100))
	}
	return nil
}

func (c *cli) verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "JSON output")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	rep, err := c.e.Verify()
	if err != nil {
		return err
	}
	if *asJSON {
		return c.json(rep)
	}
	reps := make([]string, 0, len(rep.Replicas))
	for r, n := range rep.Replicas {
		reps = append(reps, fmt.Sprintf("%s:%d", r, n))
	}
	sort.Strings(reps)
	c.printf("%d events across %d replica(s): %s\n", rep.Events, len(rep.Replicas), strings.Join(reps, " "))
	for _, p := range rep.Problems {
		c.printf("  ✗ %s\n", p)
	}
	if !rep.OK {
		return fmt.Errorf("verification failed: %d problem(s)", len(rep.Problems))
	}
	c.printf("ok: every hash, chain link and signature checks out\n")
	return nil
}

func (c *cli) heads(args []string) error {
	hs, err := c.e.Heads()
	if err != nil {
		return err
	}
	for _, h := range hs {
		c.printf("%s %d %s\n", h.Replica, h.RSeq, h.Hash)
	}
	return nil
}

func (c *cli) rebuild(args []string) error {
	if err := c.e.Rebuild(); err != nil {
		return err
	}
	c.printf("rebuilt all projections from the log\n")
	return nil
}

func (c *cli) keys(args []string) error {
	if len(args) >= 2 && (args[0] == "trust" || args[0] == "distrust") {
		return c.e.SetTrust(args[1], args[0] == "trust", "")
	}
	ks, err := c.e.Keys()
	if err != nil {
		return err
	}
	for _, k := range ks {
		t := "untrusted (quarantined)"
		if k.Trusted {
			t = "trusted"
		}
		c.printf("%s  %-24s %-23s %d events  replica %s\n", k.KeyID, k.Actor, t, k.Events, k.Replica)
	}
	return nil
}

func (c *cli) remote(args []string) error {
	if len(args) >= 1 && args[0] == "add" {
		fs := flag.NewFlagSet("remote add", flag.ContinueOnError)
		pullOnly := fs.Bool("pull-only", false, "read from it, never write (e.g. a team's shared memory)")
		pos, err := parse(fs, args[1:])
		if err != nil {
			return err
		}
		if err := need(pos, 2, "smem remote add <name> <dir> [--pull-only]"); err != nil {
			return err
		}
		return c.e.AddRemote(pos[0], pos[1], *pullOnly)
	}
	rs, err := c.e.Remotes()
	if err != nil {
		return err
	}
	if len(rs) == 0 {
		c.printf("no remotes (local only). Add one: smem remote add origin /path/to/shared/dir\n")
	}
	for n, r := range rs {
		mode := ""
		if r.PullOnly {
			mode = "  (pull-only)"
		}
		c.printf("%s  %s%s\n", n, r.Dir, mode)
	}
	return nil
}

func (c *cli) pickRemote(args []string) (smem.DirRemote, error) {
	rs, err := c.e.Remotes()
	if err != nil {
		return smem.DirRemote{}, err
	}
	name := "origin"
	if len(args) > 0 {
		name = args[0]
	} else if len(rs) == 1 {
		for n := range rs {
			name = n
		}
	}
	r, ok := rs[name]
	if !ok {
		return smem.DirRemote{}, fmt.Errorf("no remote %q (smem remote add %s <dir>)", name, name)
	}
	return r, nil
}

func (c *cli) report(rep *smem.ImportReport) {
	c.printf("pulled %d new event(s), %d already present", rep.Accepted, rep.Skipped)
	if rep.Rebuilt {
		c.printf(" (replayed projections)")
	}
	c.printf("\n")
	if rep.Quarantined > 0 {
		c.printf("  %d event(s) signed by untrusted keys are quarantined: not shown until `smem keys trust <key-id>`\n", rep.Quarantined)
	}
	if rep.Clamped > 0 {
		c.printf("  %d backdated event(s) are projected at the clamped time (sync.max_backdate)\n", rep.Clamped)
	}
	for _, r := range rep.Rejected {
		c.printf("  ✗ rejected %s\n", r)
	}
	c.flags(rep.Flags)
}

func (c *cli) sync(args []string) error {
	r, err := c.pickRemote(args)
	if err != nil {
		return err
	}
	rep, n, err := c.e.Sync(r)
	if rep != nil {
		c.report(rep)
	}
	if err != nil {
		return err
	}
	if !r.PullOnly {
		c.printf("pushed %d event(s)\n", n)
	}
	return nil
}

func (c *cli) push(args []string) error {
	r, err := c.pickRemote(args)
	if err != nil {
		return err
	}
	if r.PullOnly {
		return errors.New("that remote is pull-only")
	}
	n, err := c.e.Push(r)
	if err != nil {
		return err
	}
	c.printf("pushed %d event(s)\n", n)
	return nil
}

func (c *cli) pull(args []string) error {
	r, err := c.pickRemote(args)
	if err != nil {
		return err
	}
	rep, err := c.e.Pull(r)
	if err != nil {
		return err
	}
	c.report(rep)
	return nil
}

func (c *cli) export(args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	replica := fs.String("replica", "", "only this replica's feed")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	_, err := c.e.Export(c.out, *replica)
	return err
}

func (c *cli) importCmd(args []string) error {
	if err := need(args, 1, "smem import <file|->"); err != nil {
		return err
	}
	r := c.in
	if args[0] != "-" {
		f, err := os.Open(args[0])
		if err != nil {
			return err
		}
		defer f.Close() //nolint:errcheck // read-only
		r = f
	}
	evs, err := smem.ReadEvents(r)
	if err != nil {
		return err
	}
	rep, err := c.e.Import(evs)
	if err != nil {
		return err
	}
	c.report(rep)
	return nil
}

func (c *cli) factcheck(args []string) error {
	fs := flag.NewFlagSet("factcheck", flag.ContinueOnError)
	due := fs.Bool("due", false, "check memories whose confidence has decayed")
	threshold := fs.Float64("threshold", 0.6, "with --due: confidence below which a memory is due")
	limit := fs.Int("limit", 10, "with --due: max memories")
	dry := fs.Bool("dry-run", false, "record the judgment but don't reconfirm or flag")
	parallel := fs.Int("parallel", 4, "checks to run at once")
	asJSON := fs.Bool("json", false, "JSON output")
	ids, err := parse(fs, args)
	if err != nil {
		return err
	}
	if *due {
		hits, err := c.e.FactCheckDue(*threshold, *limit)
		if err != nil {
			return err
		}
		for _, h := range hits {
			ids = append(ids, h.ID)
		}
	}
	if len(ids) == 0 {
		return errors.New("usage: smem factcheck <mem>... or --due")
	}
	// Judge calls dominate and run outside the database lock, so checks
	// overlap well; results print in the order asked.
	results := make([]*smem.FactCheckResult, len(ids))
	errs := make([]error, len(ids))
	sem := make(chan struct{}, max(*parallel, 1))
	var wg sync.WaitGroup
	for i, id := range ids {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			results[i], errs[i] = c.e.FactCheck(context.Background(), id, !*dry)
		}()
	}
	wg.Wait()
	for i, r := range results {
		if errs[i] != nil {
			return fmt.Errorf("%s: %w", ids[i], errs[i])
		}
		if *asJSON {
			continue
		}
		c.printf("%s  %s %.2f by %s → %s\n    %s\n", r.Memory, r.Verdict.Label, r.Verdict.Confidence, r.DecidedBy, r.Action, oneLine(r.Content, 100))
		if r.Cached {
			c.printf("    (unchanged since judgment %s; reused)\n", r.Judgment)
		}
		if r.Verdict.Reason != "" {
			c.printf("    why: %s\n", oneLine(r.Verdict.Reason, 160))
		}
		for _, t := range r.Trail {
			a := t.Answers["relation"]
			c.printf("    %s (%s): %s %.2f, same subject %.2f, %d ms\n", t.Judge, t.Model, a.Choice, a.Confidence,
				t.Answers["same_subject"].Probability, t.LatencyMs)
		}
		for _, e := range r.Errors {
			c.printf("    ! %s\n", e)
		}
	}
	if *asJSON {
		return c.json(results)
	}
	return nil
}

func (c *cli) judges(args []string) error {
	fs := flag.NewFlagSet("judges", flag.ContinueOnError)
	ping := fs.Bool("ping", false, "send each judge a tiny question and report what happens")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	names := c.e.Judges.Names()
	if len(names) == 0 {
		c.printf("judges: none (TYPESAFE_API_KEY or OPENROUTER_API_KEY for Jev; ANTHROPIC_API_KEY, ANTHROPIC_AUTH_TOKEN, or ANTHROPIC_BASE_URL with ANTHROPIC_CUSTOM_HEADERS for Claude)\n")
	} else {
		c.printf("judges, in order: %s\n", strings.Join(names, " → "))
	}
	pol := c.e.FactCheckPolicy
	c.printf("acting needs %d agreeing check(s); cache %s; daily budget %d judge calls\n", max(pol.MinAgreeing, 1), pol.CacheTTL.D(), pol.DailyBudget)
	if len(c.e.Checkers) == 0 {
		c.printf("checkers: none (add them to the local config, %s)\n", cmp.Or(smem.LocalConfigPath(), "$SMEM_CONFIG"))
	}
	for _, k := range c.e.Checkers {
		c.printf("checker: %s\n", k.Name())
	}
	if health, err := c.e.JudgeHealth(24 * time.Hour); err == nil {
		for _, h := range health {
			c.printf("%s, last 24h: %d ok, %d failed", h.Judge, h.OK, h.Failed)
			if h.Failed > 0 {
				c.printf("; last failure: %s", h.LastError)
			}
			c.printf("\n")
		}
	}
	if *ping {
		for _, r := range smem.PingJudges(context.Background(), c.e.Judges) {
			if r.Err != "" {
				c.printf("  ✗ %s: %s\n", r.Judge, r.Err)
			} else {
				c.printf("  ✓ %s (%s) answered in %d ms\n", r.Judge, r.Model, r.LatencyMs)
			}
		}
	}
	return nil
}

func oneLine(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > n {
		s = string(r[:n-1]) + "…"
	}
	return s
}

func (c *cli) mcp(args []string) error {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	fs.Bool("init", false, "create .smem/smem.db here if no store is found")
	session := fs.String("session", "", "file everything under this session (default: the session the hook recorded)")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	s := &mcp.Server{Engine: c.e, Version: version, Session: *session, ActorFromClient: !c.actorSet}
	return s.Serve(context.Background(), c.in, c.out)
}

func (c *cli) doctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	ping := fs.Bool("ping", false, "also send each judge a tiny question")
	asJSON := fs.Bool("json", false, "JSON output")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	var cfgErr error
	if c.e == nil {
		c.cfg, cfgErr = smem.LoadConfig(smem.LocalConfigPath())
	}
	checks := smem.Doctor(context.Background(), c.e, c.cfg, cfgErr, *ping)
	if *asJSON {
		return c.json(checks)
	}
	failed := false
	for _, ch := range checks {
		mark := map[string]string{"ok": "✓", "warn": "!", "fail": "✗"}[ch.Status]
		c.printf("%s %-14s %s\n", mark, ch.Name, ch.Detail)
		failed = failed || ch.Status == "fail"
	}
	if failed {
		return errors.New("some checks failed")
	}
	return nil
}

func (c *cli) stats(args []string) error {
	fs := flag.NewFlagSet("stats", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "JSON output")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	s, err := c.e.Stats()
	if err != nil {
		return err
	}
	if *asJSON {
		return c.json(s)
	}
	c.printf("events      %d (%d in the last 24h, %d in 7 days), %.1f MB\n", s.Events, s.Last24h, s.Last7d, float64(s.Bytes)/1e6)
	types := make([]string, 0, len(s.ByType))
	for t := range s.ByType {
		types = append(types, t)
	}
	sort.Slice(types, func(i, j int) bool { return s.ByType[types[i]] > s.ByType[types[j]] })
	for _, t := range types {
		c.printf("  %-20s %d\n", t, s.ByType[t])
	}
	c.printf("replicas    %d\n", len(s.ByReplica))
	c.printf("memories    %v\n", s.Memories)
	c.printf("decisions   %d   actions %d   judgments %d\n", s.Decisions, s.Actions, s.Judgments)
	if s.Quarantined > 0 {
		c.printf("quarantined %d event(s) from untrusted keys\n", s.Quarantined)
	}
	if s.Spool > 0 {
		c.printf("spool       %d tool call(s) waiting\n", s.Spool)
	}
	return nil
}

func (c *cli) failure(args []string) error {
	fs := flag.NewFlagSet("failure", flag.ContinueOnError)
	ref := fs.String("ref", "", "test path, commit, bead or URL")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if err := need(pos, 2, `smem failure <label> "<what went wrong>" [--ref]`); err != nil {
		return err
	}
	id, promoted, err := c.e.RecordFailure(smem.FailureInput{Label: pos[0], Summary: strings.Join(pos[1:], " "), Ref: *ref})
	if err != nil {
		return err
	}
	c.printf("%s\n", id)
	for _, r := range promoted {
		c.printf("  admitted %s: enough %q failures now\n", r, pos[0])
	}
	return nil
}

func (c *cli) failuresCmd(args []string) error {
	fs := flag.NewFlagSet("failures", flag.ContinueOnError)
	label := fs.String("label", "", "only this label")
	limit := fs.Int("limit", 50, "max")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	fsl, err := c.e.Failures(*label, *limit)
	if err != nil {
		return err
	}
	for _, f := range fsl {
		c.printf("%s  %s  %-20s %s\n", f.ID, f.At.Local().Format("2006-01-02 15:04"), f.Label, oneLine(f.Summary, 90))
	}
	return nil
}

func (c *cli) rules(args []string) error {
	sub := "list"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = args[0], args[1:]
	}
	outcome := func(o *smem.RuleOutcome, err error) error {
		if err != nil {
			return err
		}
		if o.Admitted {
			c.printf("%s admitted: %s\n", o.ID, o.Reason)
		} else {
			c.printf("%s held (proposed, not active): %s\n", o.ID, o.Reason)
		}
		for _, r := range o.Retired {
			c.printf("  retired %s\n", r)
		}
		return nil
	}
	switch sub {
	case "list":
		fs := flag.NewFlagSet("rules", flag.ContinueOnError)
		status := fs.String("status", "active", "proposed, active, suspect, retired, rejected, or all")
		asJSON := fs.Bool("json", false, "JSON output")
		if _, err := parse(fs, args); err != nil {
			return err
		}
		st := *status
		if st == "all" {
			st = ""
		}
		rs, err := c.e.Rules(st)
		if err != nil {
			return err
		}
		if *asJSON {
			return c.json(rs)
		}
		if len(rs) == 0 {
			c.printf("no %s rules\n", *status)
		}
		for _, r := range rs {
			why := r.Basis
			if r.Status == "proposed" {
				why = "held: " + r.Held
			}
			c.printf("%s [%s] %s\n    %s\n", r.ID, r.Status, oneLine(r.Text, 110), oneLine(why, 120))
		}
		return nil
	case "propose":
		fs := flag.NewFlagSet("rules propose", flag.ContinueOnError)
		var in smem.RuleInput
		var failures list
		fs.StringVar(&in.Why.Kind, "why", "", "requested, incident or decision")
		fs.StringVar(&in.Why.By, "by", "", "who asked for it")
		fs.StringVar(&in.Why.Quote, "quote", "", "their words")
		fs.StringVar(&in.Why.Transcript, "transcript", "", "where they said it")
		fs.StringVar(&in.Why.Decision, "decision", "", "the decision it carries out")
		fs.StringVar(&in.Why.EnforcedBy, "enforced-by", "", "the test or check that enforces it, e.g. test:./ci/lint_test.go")
		fs.StringVar(&in.Label, "label", "", "the failure label it addresses")
		fs.Var(&failures, "failures", "fail- ids it answers")
		fs.StringVar(&in.Scope, "scope", "", "scope (default scopes.write)")
		pos, err := parse(fs, args)
		if err != nil {
			return err
		}
		if err := need(pos, 1, `smem rules propose "<rule>" --why ...`); err != nil {
			return err
		}
		in.Text, in.Why.Failures = strings.Join(pos, " "), failures
		return outcome(c.e.ProposeRule(in))
	case "approve":
		fs := flag.NewFlagSet("rules approve", flag.ContinueOnError)
		by := fs.String("by", "", "who approves")
		note := fs.String("note", "", "why")
		pos, err := parse(fs, args)
		if err != nil {
			return err
		}
		if err := need(pos, 1, "smem rules approve <rule> --by <who>"); err != nil {
			return err
		}
		for _, id := range pos {
			if err := outcome(c.e.ApproveRule(id, *by, *note)); err != nil {
				return err
			}
		}
		return nil
	case "reject", "retire", "reaffirm", "violated":
		fs := flag.NewFlagSet("rules "+sub, flag.ContinueOnError)
		reason := fs.String("reason", "", "why")
		pos, err := parse(fs, args)
		if err != nil {
			return err
		}
		if err := need(pos, 1, "smem rules "+sub+" <rule>... --reason"); err != nil {
			return err
		}
		fn := map[string]func(string, string) error{"reject": c.e.RejectRule, "retire": c.e.RetireRule,
			"reaffirm": c.e.ReaffirmRule, "violated": c.e.RuleViolated}[sub]
		for _, id := range pos {
			if err := fn(id, *reason); err != nil {
				return err
			}
		}
		return nil
	case "merge":
		fs := flag.NewFlagSet("rules merge", flag.ContinueOnError)
		text := fs.String("text", "", "the merged rule")
		pos, err := parse(fs, args)
		if err != nil {
			return err
		}
		if *text == "" || len(pos) < 2 {
			return errors.New(`usage: smem rules merge <rule> <rule>... --text "<merged rule>"`)
		}
		return outcome(c.e.MergeRules(pos, *text, smem.Justification{}))
	case "rationalize":
		fs := flag.NewFlagSet("rules rationalize", flag.ContinueOnError)
		var imports list
		fs.Var(&imports, "import", "files to import rules from, e.g. CLAUDE.md,.claude/rules/testing.md")
		judges := fs.Bool("judges", false, "ask judges about rule pairs that might mean the same thing")
		asJSON := fs.Bool("json", false, "JSON output")
		if _, err := parse(fs, args); err != nil {
			return err
		}
		if len(imports) > 0 {
			ids, err := c.e.ImportRules(imports)
			if err != nil {
				return err
			}
			c.printf("imported %d rule(s) as proposals\n\n", len(ids))
		}
		rep, err := c.e.RationalizeRules(context.Background(), *judges)
		if err != nil {
			return err
		}
		if *asJSON {
			return c.json(rep)
		}
		c.rulesReport(rep)
		return nil
	case "render":
		fs := flag.NewFlagSet("rules render", flag.ContinueOnError)
		file := fs.String("file", "", "file to write (default rules.file, CLAUDE.md)")
		check := fs.Bool("check", false, "change nothing; fail if the file is out of date")
		if _, err := parse(fs, args); err != nil {
			return err
		}
		changed, err := c.e.RenderRules(*file, *check)
		if err != nil {
			return err
		}
		switch {
		case *check && changed:
			return errors.New("rules block is out of date; run smem rules render")
		case changed:
			c.printf("updated %s\n", cmp.Or(*file, c.e.Policy.Rules.File))
		default:
			c.printf("up to date\n")
		}
		return nil
	}
	return fmt.Errorf("unknown rules command %q (see smem help)", sub)
}

func (c *cli) rulesReport(rep *smem.RulesReport) {
	section := func(title string, n int, fn func()) {
		if n == 0 {
			return
		}
		c.printf("%s (%d)\n", title, n)
		fn()
		c.printf("\n")
	}
	section("Duplicates: merge or retire one", len(rep.Duplicates), func() {
		for _, p := range rep.Duplicates {
			how := fmt.Sprintf("word overlap %.2f", p.Similarity)
			if p.JudgedBy != "" {
				how = "same meaning per " + p.JudgedBy
			}
			c.printf("  %s ~ %s (%s)\n    %s\n    %s\n", p.A.ID, p.B.ID, how, oneLine(p.A.Text, 100), oneLine(p.B.Text, 100))
		}
	})
	section("Promotable: held proposals whose reason now holds", len(rep.Promotable), func() {
		for _, r := range rep.Promotable {
			c.printf("  %s %s\n", r.ID, oneLine(r.Text, 110))
		}
	})
	section("Held: no reason that holds up (approve, reject, or wait for failures)", len(rep.Held), func() {
		for _, r := range rep.Held {
			src := ""
			if r.Source != "" {
				src = " (" + r.Source + ")"
			}
			c.printf("  %s %s%s\n    %s\n", r.ID, oneLine(r.Text, 100), src, oneLine(r.Held, 120))
		}
	})
	section("Suspect: what they rest on changed (reaffirm or retire)", len(rep.Suspect), func() {
		for _, r := range rep.Suspect {
			c.printf("  %s %s\n", r.ID, oneLine(r.Text, 110))
		}
	})
	section("Ineffective: failures they were meant to prevent happened since", len(rep.Ineffective), func() {
		for _, rc := range rep.Ineffective {
			c.printf("  %s %d × %q: %s\n", rc.Rule.ID, rc.Count, rc.Rule.Label, oneLine(rc.Rule.Text, 90))
		}
	})
	section("Violated", len(rep.Violated), func() {
		for _, rc := range rep.Violated {
			c.printf("  %s %d time(s): %s\n", rc.Rule.ID, rc.Count, oneLine(rc.Rule.Text, 90))
		}
	})
	section("Stale: no activity for rules.stale_after", len(rep.Stale), func() {
		for _, r := range rep.Stale {
			c.printf("  %s last active %s: %s\n", r.ID, r.LastActivity.Local().Format("2006-01-02"), oneLine(r.Text, 90))
		}
	})
	section("Over the cap", len(rep.OverCap), func() {
		for _, s := range rep.OverCap {
			c.printf("  %s\n", s)
		}
	})
	for _, n := range rep.Notes {
		c.printf("note: %s\n", n)
	}
	if len(rep.Duplicates)+len(rep.Promotable)+len(rep.Held)+len(rep.Suspect)+len(rep.Ineffective)+len(rep.Violated)+len(rep.Stale)+len(rep.OverCap) == 0 {
		c.printf("rules look healthy\n")
	}
}
