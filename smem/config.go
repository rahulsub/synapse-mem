package smem

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go/v2"
	"github.com/anthropics/anthropic-sdk-go/v2/option"

	"github.com/rahulsub/synapse-mem/judge"
)

// Configuration comes from two files, merged over the defaults:
//
//   - the project config, .smem/config.json next to the database. It may be
//     committed, so it can only hold settings that are safe to take from a
//     repository: nothing that runs code, sends data somewhere else, or
//     decides whose events are trusted.
//   - the local config, $SMEM_CONFIG or <user config dir>/smem/config.json.
//     It belongs to the machine or agent and may set everything.
//
// The local config wins over the project config, and environment variables
// (SMEM_ACTOR, SMEM_KEY_DIR, API keys) win over both. Secrets never go in
// either file.
type Config struct {
	Policy
	Judges    JudgesConfig    `json:"judges"`
	FactCheck FactCheckPolicy `json:"factcheck"`

	// Local only.
	Actor     string          `json:"actor,omitempty"`
	Checkers  []CheckerConfig `json:"checkers,omitempty"`
	Endpoints EndpointsConfig `json:"endpoints"`
	Keys      KeysConfig      `json:"keys"`
	Trust     TrustConfig     `json:"trust"`

	// Sources lists the files the config was read from.
	Sources []string `json:"-"`
}

// localOnly are the top-level keys a project config may not set.
var localOnly = []string{"actor", "checkers", "endpoints", "keys", "trust"}

// Policy is the behavior that a project config may set.
type Policy struct {
	Beads      BeadsPolicy      `json:"beads"`
	Scopes     ScopesPolicy     `json:"scopes"`
	Context    ContextPolicy    `json:"context"`
	Decay      DecayPolicy      `json:"decay"`
	Recall     RecallPolicy     `json:"recall"`
	Sync       SyncPolicy       `json:"sync"`
	Hooks      HooksPolicy      `json:"hooks"`
	Redaction  RedactionPolicy  `json:"redaction"`
	MCP        MCPPolicy        `json:"mcp"`
	Rules      RulesPolicy      `json:"rules"`
	Confidence ConfidencePolicy `json:"confidence"`
}

// ConfidencePolicy tunes how evidence changes a memory's confidence.
type ConfidencePolicy struct {
	// ConfirmBoost is the share of remaining doubt one confirmation
	// removes: 0.5 takes 0.8 to 0.9, then 0.95. 0 only resets the clock.
	ConfirmBoost float64 `json:"confirm_boost"`
}

// BeadsPolicy says which references are bead (issue) ids.
type BeadsPolicy struct {
	// Prefixes are bead id prefixes, e.g. ["bd", "dojo"] for bd-a1b2 and
	// dojo-j6lv.1 (child ids included).
	Prefixes []string `json:"prefixes"`
	// Detect also reads the prefix from .beads/config.yaml.
	Detect bool `json:"detect"`
}

// ScopesPolicy controls which memories an agent sees and writes.
type ScopesPolicy struct {
	// Read limits recall and context to these scopes. Memories with no
	// scope are always visible. Entries are globs: "project:dojo*",
	// "agent:reviewer", "team". Empty means everything.
	Read []string `json:"read"`
	// Write is the scope given to new memories that don't name one.
	Write string `json:"write"`
}

// ContextPolicy controls what the session-start hook injects.
type ContextPolicy struct {
	Budget int `json:"budget"`
	// Kinds limits injected memories to these kinds (empty: all).
	Kinds []string `json:"kinds"`
	// Reinforce counts an injection as a use. Off by default: memories
	// would otherwise keep themselves alive just by being shown.
	Reinforce bool `json:"reinforce"`
	// On lists the SessionStart sources that inject: startup, resume,
	// clear, compact. Default startup and clear: a resumed session already
	// has the context, and a compacted one has its summary.
	On []string `json:"on"`
}

// DecayPolicy chooses the clock memories fade by.
type DecayPolicy struct {
	// Clock is "active" (default) or "wall". On the active clock, time an
	// agent spends idle beyond IdleAfter doesn't count toward forgetting,
	// so an agent that is quiet for a week comes back with its memory.
	// Confidence (is it still true?) always uses the wall clock.
	Clock     string   `json:"clock"`
	IdleAfter Duration `json:"idle_after"`
}

// RecallPolicy tunes recall logging.
type RecallPolicy struct {
	// DedupeWindow skips logging a recall identical to one logged in the
	// same session within this window (same query, same results).
	DedupeWindow Duration `json:"dedupe_window"`
}

// SyncPolicy bounds what imports may claim about time.
type SyncPolicy struct {
	MaxFutureSkew Duration `json:"max_future_skew"`
	MaxBackdate   Duration `json:"max_backdate"`
}

// HooksPolicy tunes the Claude Code hooks.
type HooksPolicy struct {
	// Spool makes post-tool-use write a small file instead of taking the
	// database lock; the next writer folds it in.
	Spool bool `json:"spool"`
	// LockTimeout is how long a hook waits for the database lock.
	LockTimeout Duration `json:"lock_timeout"`
	// LinkDecisions links a tool call to a decision: "unambiguous" (the
	// session's latest decision, only if it is the only one made in that
	// session within LinkWindow), "latest", or "never".
	LinkDecisions string   `json:"link_decisions"`
	LinkWindow    Duration `json:"link_window"`
	// SkipTools are tool names (globs) never recorded.
	SkipTools []string `json:"skip_tools"`
	// RequireStore makes hooks fail visibly when no store is found.
	RequireStore bool `json:"require_store"`
}

// RedactionPolicy extends secret redaction. It can add, never remove.
type RedactionPolicy struct {
	// MinEnvValue is the shortest credential env value redacted verbatim.
	MinEnvValue int `json:"min_env_value"`
	// SecretEnv names more environment variables whose values are secrets.
	SecretEnv []string `json:"secret_env"`
	// Patterns are more regular expressions to redact.
	Patterns []string `json:"patterns"`
}

// MCPPolicy tunes the MCP server.
type MCPPolicy struct {
	// Disable hides tools, e.g. ["memory_remember"] where another tool
	// (bd remember) owns plain memories.
	Disable []string `json:"disable"`
	// Instructions replaces the server's usage instructions.
	Instructions string `json:"instructions"`
}

// JudgesConfig chooses which judges run and when.
type JudgesConfig struct {
	Jev struct {
		// Disabled turns Jev off even when a key is present.
		Disabled bool   `json:"disabled"`
		Model    string `json:"model"`
		JudgeLimits
	} `json:"jev"`
	Claude struct {
		// When is "escalate" (default: only when Jev is unsure or
		// unavailable, or to make up min_agreeing), "always" (a second
		// opinion on every check), or "never".
		When      string `json:"when"`
		Model     string `json:"model"` // SMEM_JUDGE_MODEL overrides, e.g. a gateway-prefixed id
		Effort    string `json:"effort"`
		MaxTokens int64  `json:"max_tokens"`
		JudgeLimits
	} `json:"claude"`
}

// JudgeLimits keeps a judge from overloading shared seats.
type JudgeLimits struct {
	// MaxAttempts per call, with exponential backoff from 1s (default 4).
	MaxAttempts int `json:"max_attempts"`
	// MaxConcurrent calls per process (default 2).
	MaxConcurrent int `json:"max_concurrent"`
}

func (l JudgeLimits) apply(r *judge.Retry, lim *judge.Limiter) {
	if l.MaxAttempts > 0 {
		r.Attempts = l.MaxAttempts
	}
	if l.MaxConcurrent > 0 {
		*lim = judge.NewLimiter(l.MaxConcurrent)
	}
}

// EndpointsConfig points judges at other servers, such as a gateway.
// Local only: a committed endpoint could send your API key elsewhere.
type EndpointsConfig struct {
	Jev    string `json:"jev"`
	Claude string `json:"claude"`
}

// KeysConfig sets where signing keys live.
type KeysConfig struct {
	Dir      string `json:"dir"`
	AllowNew bool   `json:"allow_new"`
}

// TrustConfig trusts keys in advance, e.g. a team curator's key.
type TrustConfig struct {
	Keys []string `json:"keys"`
}

// CheckerConfig declares an external checker command.
type CheckerConfig struct {
	Name    string   `json:"name"`
	Command []string `json:"command"`
	Match   string   `json:"match,omitempty"` // regexp on memory content
	Kinds   []string `json:"kinds,omitempty"`
	Timeout string   `json:"timeout,omitempty"`
	// Env names extra environment variables the checker may see. It gets
	// only PATH, HOME, USER, LANG, LC_ALL, TZ and TMPDIR otherwise.
	Env []string `json:"env,omitempty"`
}

// Duration is a time.Duration written as "90s", "24h" or "7d".
type Duration time.Duration

// D returns d as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// MarshalJSON implements json.Marshaler.
func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

// UnmarshalJSON implements json.Unmarshaler.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration must be a string like \"24h\": %s", b)
	}
	v, err := parseDuration(s)
	*d = Duration(v)
	return err
}

func parseDuration(s string) (time.Duration, error) {
	if n, ok := strings.CutSuffix(s, "d"); ok {
		var days float64
		if _, err := fmt.Sscanf(n, "%g", &days); err != nil {
			return 0, fmt.Errorf("bad duration %q", s)
		}
		return time.Duration(days * 24 * float64(time.Hour)), nil
	}
	return time.ParseDuration(s)
}

// DefaultPolicy is the behavior with no config.
func DefaultPolicy() Policy {
	return Policy{
		Beads:      BeadsPolicy{Prefixes: []string{"bd"}, Detect: true},
		Context:    ContextPolicy{Budget: 4000, On: []string{"startup", "clear"}},
		Decay:      DecayPolicy{Clock: "active", IdleAfter: Duration(24 * time.Hour)},
		Recall:     RecallPolicy{DedupeWindow: Duration(10 * time.Minute)},
		Sync:       SyncPolicy{MaxFutureSkew: Duration(5 * time.Minute), MaxBackdate: Duration(30 * 24 * time.Hour)},
		Hooks:      HooksPolicy{Spool: true, LockTimeout: Duration(2 * time.Second), LinkDecisions: "unambiguous", LinkWindow: Duration(30 * time.Minute)},
		Redaction:  RedactionPolicy{MinEnvValue: 6},
		Rules:      DefaultRulesPolicy(),
		Confidence: ConfidencePolicy{ConfirmBoost: 0.5},
	}
}

// DefaultConfig is the configuration with no files.
func DefaultConfig() *Config {
	return &Config{Policy: DefaultPolicy(), FactCheck: DefaultFactCheckPolicy()}
}

// ConfigPath is where the project config for a database lives.
func ConfigPath(dbPath string) string { return filepath.Join(filepath.Dir(dbPath), "config.json") }

// LocalConfigPath is where the local config lives: $SMEM_CONFIG, or the
// user config dir. Agents with an ephemeral home should set SMEM_CONFIG.
func LocalConfigPath() string {
	if p := os.Getenv("SMEM_CONFIG"); p != "" {
		return p
	}
	d, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(d, "smem", "config.json")
}

// LoadConfigFor reads the project config for the database at dbPath and the
// local config, over the defaults.
func LoadConfigFor(dbPath string) (*Config, error) {
	cfg := DefaultConfig()
	if err := cfg.overlay(ConfigPath(dbPath), true); err != nil {
		return nil, err
	}
	if p := LocalConfigPath(); p != "" {
		if err := cfg.overlay(p, false); err != nil {
			return nil, err
		}
	}
	return cfg, nil
}

// LoadConfig reads one config file over the defaults, as a local config.
func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()
	return cfg, cfg.overlay(path, false)
}

func (c *Config) overlay(path string, project bool) error {
	b, err := os.ReadFile(path) //nolint:gosec // the config files are the point
	if os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	if project {
		var top map[string]json.RawMessage
		if err := json.Unmarshal(b, &top); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		var bad []string
		for _, k := range localOnly {
			if _, ok := top[k]; ok {
				bad = append(bad, k)
			}
		}
		if len(bad) > 0 {
			sort.Strings(bad)
			return fmt.Errorf("%s: %s can only be set in the local config (%s), which is not part of the repository: "+
				"a cloned repository must not be able to run commands, redirect API keys or choose whom to trust",
				path, strings.Join(bad, ", "), cmp(LocalConfigPath(), "$SMEM_CONFIG"))
		}
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(c); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	c.Sources = append(c.Sources, path)
	return nil
}

// Configure applies cfg: policy, judges, checkers, keys and trust. API keys
// come from the environment:
//
//	TYPESAFE_API_KEY (or OPENROUTER_API_KEY)     enables Jev
//	ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN    enables Claude (Haiku 5.5 by default)
//
// ANTHROPIC_BASE_URL and endpoints.claude point Claude at a gateway.
func (e *Engine) Configure(cfg *Config) error {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	e.Policy = cfg.Policy
	e.FactCheckPolicy = cfg.FactCheck
	if os.Getenv("SMEM_ACTOR") == "" && cfg.Actor != "" {
		e.Actor = cfg.Actor
	}
	if os.Getenv("SMEM_KEY_DIR") == "" && cfg.Keys.Dir != "" {
		e.KeyDir = cfg.Keys.Dir
	}
	e.AllowNewKey = cfg.Keys.AllowNew
	r, err := NewRedactor(cfg.Redaction)
	if err != nil {
		return err
	}
	e.redactor = r
	if err := e.configureBeads(); err != nil {
		return err
	}
	if err := e.configureJudges(cfg); err != nil {
		return err
	}
	if err := e.configureCheckers(cfg); err != nil {
		return err
	}
	if len(cfg.Trust.Keys) > 0 {
		want := map[string]bool{}
		for _, k := range cfg.Trust.Keys {
			want[k] = true
		}
		return e.setTrust(want, "trusted in "+cmp(LocalConfigPath(), "local config"))
	}
	return nil
}

func (e *Engine) configureJudges(cfg *Config) error {
	var stages []judge.Stage
	if !cfg.Judges.Jev.Disabled {
		var j *judge.Jev
		if k := os.Getenv("TYPESAFE_API_KEY"); k != "" {
			j = judge.NewJev(k)
			if u := cmp(cfg.Endpoints.Jev, os.Getenv("TYPESAFE_BASE_URL")); u != "" {
				j.BaseURL = u
			}
		} else if k := os.Getenv("OPENROUTER_API_KEY"); k != "" {
			j = judge.NewJevOpenRouter(k)
		}
		if j != nil {
			if cfg.Judges.Jev.Model != "" {
				j.Model = cfg.Judges.Jev.Model
			}
			cfg.Judges.Jev.apply(&j.Retry, &j.Limit)
			stages = append(stages, judge.Stage{Judge: j})
		}
	}
	when := cmp(cfg.Judges.Claude.When, "escalate")
	if !contains([]string{"escalate", "always", "never"}, when) {
		return fmt.Errorf("judges.claude.when must be escalate, always or never, not %q", when)
	}
	headers := customHeaders(os.Getenv("ANTHROPIC_CUSTOM_HEADERS"))
	gateway := cmp(cfg.Endpoints.Claude, os.Getenv("ANTHROPIC_BASE_URL")) != "" && len(headers) > 0
	if when != "never" && (os.Getenv("ANTHROPIC_API_KEY") != "" || os.Getenv("ANTHROPIC_AUTH_TOKEN") != "" || gateway) {
		// The SDK reads the key or token and ANTHROPIC_BASE_URL itself.
		// ANTHROPIC_CUSTOM_HEADERS is a Claude Code convention the SDK
		// doesn't read, so it is passed on here.
		var opts []option.RequestOption
		if cfg.Endpoints.Claude != "" {
			opts = append(opts, option.WithBaseURL(cfg.Endpoints.Claude))
		}
		for _, h := range headers {
			opts = append(opts, option.WithHeader(h[0], h[1]))
		}
		c := judge.NewClaude(opts...)
		if m := cmp(os.Getenv("SMEM_JUDGE_MODEL"), cfg.Judges.Claude.Model); m != "" {
			c.Model = m
		}
		cfg.Judges.Claude.apply(&c.Retry, &c.Limit)
		if cfg.Judges.Claude.Effort != "" {
			c.Effort = anthropic.OutputConfigEffort(cfg.Judges.Claude.Effort)
		}
		if cfg.Judges.Claude.MaxTokens > 0 {
			c.MaxTokens = cfg.Judges.Claude.MaxTokens
		}
		stages = append(stages, judge.Stage{Judge: c, Always: when == "always"})
	}
	e.Judges = judge.Cascade{Stages: stages}
	return nil
}

func (e *Engine) configureCheckers(cfg *Config) error {
	e.Checkers = nil
	for _, cc := range cfg.Checkers {
		if cc.Name == "" || len(cc.Command) == 0 {
			return fmt.Errorf("checker needs a name and a command")
		}
		c := &CommandChecker{CheckName: cc.Name, Command: cc.Command, Kinds: cc.Kinds, Env: cc.Env,
			Dir: filepath.Dir(filepath.Dir(e.path))}
		if cc.Match != "" {
			re, err := regexp.Compile(cc.Match)
			if err != nil {
				return fmt.Errorf("checker %s: %w", cc.Name, err)
			}
			c.Match = re
		}
		if cc.Timeout != "" {
			d, err := time.ParseDuration(cc.Timeout)
			if err != nil {
				return fmt.Errorf("checker %s: %w", cc.Name, err)
			}
			c.Timeout = d
		}
		e.Checkers = append(e.Checkers, c)
	}
	return nil
}

var beadsPrefixLine = regexp.MustCompile(`(?m)^\s*issue[-_]prefix\s*:\s*["']?([A-Za-z0-9_-]+)`)

// configureBeads compiles the bead id pattern from the configured prefixes
// and, with detect, the prefix in .beads/config.yaml.
func (e *Engine) configureBeads() error {
	prefixes := append([]string(nil), e.Policy.Beads.Prefixes...)
	if e.Policy.Beads.Detect {
		root := filepath.Dir(filepath.Dir(e.path))
		if b, err := os.ReadFile(filepath.Join(root, ".beads", "config.yaml")); err == nil { //nolint:gosec // fixed path in the project
			if m := beadsPrefixLine.FindSubmatch(b); m != nil {
				prefixes = append(prefixes, string(m[1]))
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	var alts []string
	for _, p := range prefixes {
		if p = strings.TrimSuffix(strings.TrimSpace(p), "-"); p != "" {
			alts = append(alts, regexp.QuoteMeta(p))
		}
	}
	e.beadRe = nil
	if len(alts) > 0 {
		// prefix-hash, with optional .N child segments: dojo-j6lv, dojo-j6lv.1.2
		e.beadRe = regexp.MustCompile(`^(?:` + strings.Join(alts, "|") + `)-[A-Za-z0-9]+(?:\.[0-9]+)*$`)
	}
	return nil
}

// IsBead reports whether ref is a bead id under the configured prefixes.
func (e *Engine) IsBead(ref string) bool {
	if e.beadRe == nil {
		return false
	}
	return e.beadRe.MatchString(ref)
}

// customHeaders parses ANTHROPIC_CUSTOM_HEADERS: "Name: value" lines.
func customHeaders(s string) [][2]string {
	var out [][2]string
	for _, line := range strings.Split(s, "\n") {
		name, value, ok := strings.Cut(line, ":")
		if name, value = strings.TrimSpace(name), strings.TrimSpace(value); ok && name != "" && value != "" {
			out = append(out, [2]string{name, value})
		}
	}
	return out
}
