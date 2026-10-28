# synapse-mem (`smem`)

Embedded memory for agents. Memories have two timelines and decay with time
and disuse. Decisions record why they were made and get flagged when what
they relied on changes. Everything is an Ed25519-signed, hash-chained,
append-only event log that works locally or syncs between machines.

Design: [docs/DESIGN.md](docs/DESIGN.md) · Configuration: [docs/CONFIG.md](docs/CONFIG.md)

## Install

**Binary**, from a GitHub release (macOS and Linux, arm64 and amd64). The
script verifies the checksum:

```sh
curl -fsSL https://raw.githubusercontent.com/rahulsub/synapse-mem/main/scripts/install.sh | sh
# or a version and directory: sh install.sh v0.4.0 /persist/bin
```

On agents whose home directory doesn't survive a restart, install to
persistent storage.

**With Go** (1.27+; no cgo needed):

```sh
go install github.com/rahulsub/synapse-mem/cmd/smem@latest
```

Or build from a checkout with `make build` (`make dist` for every platform).

Then run `smem doctor`. It checks the store, the config files, your identity
and key, judges (`--ping` sends each a tiny question), trust, the spool and
remotes.

### Claude Code

**Per project, kept with the repo** (best for agents whose `~/.claude` is
lost on restart):

```sh
smem init --claude-code     # writes .mcp.json and the hooks in .claude/settings.json, keeping what's there
```

**As a plugin, per user:**

```
/plugin marketplace add rahulsub/synapse-mem
/plugin install smem@synapse-mem
```

The plugin adds the `smem` MCP server (memory and decision tools), the
session-start and post-tool-use hooks, and a skill on when to use them. It
needs the `smem` binary on `PATH` (or `SMEM_BIN`). It creates `.smem/` in each
project on first use, already git-ignored except `config.json`.

### Any MCP agent

```json
{"mcpServers": {"smem": {"command": "smem", "args": ["mcp", "--init"]}}}
```

Tools: `memory_recall`, `memory_context`, `memory_remember`, `memory_update`,
`memory_invalidate`, `memory_signal`, `decision_record`, `decision_outcome`,
`why`, `review`, `factcheck`, `failure_record`, `rule_propose`, `rules_list`.
Any of them can be turned off with `mcp.disable`.

### Agents that call the CLI

A lone `-` reads content from stdin, so it stays out of the process list;
`decide` and `action` take their fields as JSON with `--input -`:

```sh
echo "orders table is append-only" | smem remember - --kind fact
smem decide --input - < decision.json   # the decision_record arguments
```

### Go

```go
e, err := smem.Open(".smem/smem.db")
cfg, _ := smem.LoadConfigFor(e.Path()) // project config + local config
e.Configure(cfg) // judges from TYPESAFE_API_KEY / ANTHROPIC_API_KEY
id, err := e.Remember(smem.MemoryInput{Kind: "fact", Content: "..."})
```

### Release

`git tag v0.2.0 && git push origin v0.2.0` runs the tests and publishes
binaries with checksums via goreleaser.

## Quick tour

```sh
smem init                                   # .smem/smem.db in this directory

F=$(smem remember "orders table is append-only" --kind fact)
smem remember "prefer boring tech" --kind preference
smem recall orders --explain                # relevance × salience × confidence

D=$(smem decide --question "fix bad totals?" --choice "insert correction rows" \
      --why "append-only keeps history" \
      --reject "UPDATE in place|breaks the invariant" \
      --assume "no consumer sums raw rows|grep -r 'SUM(total)' services/" \
      --used $F --bead bd-77 | head -1)
git commit -m "Correction rows

$(smem trailer $D)"

smem invalidate $F --reason "migration 0042 added UPDATE triggers"
#   ⚠ dec-… is now suspect (because mem-… changed)
smem review
smem why $(git rev-parse --short HEAD)       # or dec-…, mem-…, asm-…, bd-77
smem recall orders --as-of 2026-03-01 --known-at 2026-03-02
smem verify                                 # every hash, link and signature
```

## Sync

```sh
smem remote add origin /shared/smem         # any shared dir: NAS, Dropbox, a git repo
smem sync                                   # pull (verify + merge), then push
smem keys                                   # keys from other replicas start untrusted
smem keys trust key-…
smem heads                                  # publish these hashes to anchor the log
```

Events signed by keys you haven't trusted are verified and stored but
**quarantined**: never recalled or injected into a prompt until you trust
the key (`smem keys trust`, or `trust.keys` in the local config). Imports
refuse events dated in the future and clamp backdated ones. A restored or
copied database continues as a new replica instead of forking the old one.

**Team memory, read-only:** a curator pushes to a shared directory. Agents
add it with `smem remote add team <dir> --pull-only`, trust only the
curator's key, and choose what they see with `scopes.read`.

## Fact-checking

```sh
export TYPESAFE_API_KEY=…      # Jev: fast, calibrated
export ANTHROPIC_API_KEY=…     # Claude Haiku 5.5: when Jev is unsure (optional)
smem judges --ping             # what's configured, and whether each judge answers
smem factcheck mem-…           # or --due to check decayed facts
```

Write your own checks in any language. Each one gets the claim as JSON on
stdin and prints a verdict, evidence, or nothing. Checkers run code, so they
go in the **local** config (`$SMEM_CONFIG`), never in the committed
`.smem/config.json`:

```json
{"checkers": [{"name": "port", "command": ["/persist/checks/check_port.py"], "match": "port \\d+"}]}
```

**Agreement.** Changing a memory takes two agreeing checks by default
(`factcheck.min_agreeing`), where a checker or a judge each counts once. A
single judge never reconfirms a memory or marks it suspect on its own;
anything short of agreement goes to review.

A contradiction marks a memory suspect, never invalid. Unchanged claims
aren't re-judged within `cache_ttl`, and `daily_budget` caps judge calls.
Evidence files must be inside the project and not on the deny list (`.env`,
keys, `.git`, …). Every check is a signed judgment you can trace with
`smem why`.

## Claude Code hooks

```json
{
  "hooks": {
    "SessionStart": [{"hooks": [{"type": "command", "command": "smem hook session-start"}]}],
    "PostToolUse":  [{"hooks": [{"type": "command", "command": "smem hook post-tool-use"}]}]
  }
}
```

**Session start.** The hook injects the most salient memories in the
session's scopes, within a budget. It does this on startup and `/clear`, not
on resume or compact (`context.on`). Being shown doesn't count as being used.

**Tool calls.** The post-tool-use hook spools each mutating tool call as a
small redacted file, so it never waits on the database. The next writer
records it, including commit shas. A call is linked to a decision only when
that's unambiguous (`hooks.link_decisions`), so parallel subagents don't get
each other's work.

**General.** Hooks find the store from the session's working directory.
They never fail the agent, unless `hooks.require_store` is set.

## Rules

Agents add rules for themselves with no record of why, until nobody can
tell which ones still matter. In smem a rule is only in force with a reason.
There are three:
- **requested:** a person asked. smem records who, and their words.
- **incident:** the same kind of failure kept happening. Failures are
  recorded with a label; ideally a test now enforces the rule.
- **decision:** it carries out a recorded decision. It's flagged if that
  decision is reverted.

Anything else is held as a proposal for a person to approve or reject.

```sh
smem failure wrong-port "worker used 8080, config says 9090"   # agents call failure_record over MCP
smem rules propose "Read ports from config; never hardcode them" --why incident --label wrong-port \
     --enforced-by test:./config/ports_test.go                  # held until the second wrong-port failure
smem rules propose "Run make test before committing" --why requested --by rahul --quote "always run the tests first"
smem rules rationalize --import CLAUDE.md,.claude/rules/testing.md --judges
smem rules render                                              # managed block in CLAUDE.md; --check for CI
smem why rule-…                                                # who asked, which failures, what it replaced
```

`rationalize` imports existing hand-written rules as held proposals. It
lists:
- duplicates, by word overlap, and paraphrases if a judge is configured;
- held proposals, and those whose reason now holds;
- suspect rules;
- ineffective rules: the failures they were meant to prevent happened anyway;
- violated rules, stale rules, and scopes over the cap.

Over MCP, agents get `failure_record`, `rule_propose` and `rules_list`, and
are told never to write rules into `CLAUDE.md` themselves. All thresholds
are configurable (`rules` in [docs/CONFIG.md](docs/CONFIG.md)).

## Configuration

Everything that differs between teams is configuration. That includes bead
prefixes (`dojo-…`), scopes, which MCP tools are on and the instructions the
agent gets, decay, sync bounds, hook behavior, extra redaction patterns, and
fact-check thresholds, cache and budget. Settings that are safe to commit go
in `.smem/config.json`. Identity, keys, trust, judge endpoints and checkers
go in the local config (`$SMEM_CONFIG`), which a cloned repo can't
override. See [docs/CONFIG.md](docs/CONFIG.md), which includes a worked
example for a beads-based fleet.

## Credentials

API keys are read from the environment only and never stored. Every payload
is redacted before it is signed, as is evidence before it goes to a judge.
Redaction removes the exact values of credential-like environment variables,
whatever their format, and common secret shapes in text: provider keys,
Stripe/Google/AWS/GitHub/GitLab/Slack tokens, JWTs, PEM blocks and fragments,
`*_KEY=` and similar assignments, auth headers, and URL passwords. Patterns
can be added in config. Command checkers get a minimal environment and never
the API keys. Details and limits: DESIGN.md §7.

## Environment

| Variable | Meaning |
|---|---|
| `SMEM_DB` | Database path (default: nearest `.smem/smem.db`) |
| `SMEM_ACTOR` | Who is writing (default `user@host`; hooks `claude-code@host`, MCP `<client>@host`). Set it for agents |
| `SMEM_CONFIG` | Local config file (default: user config dir `smem/config.json`) |
| `SMEM_BIN` | Binary the Claude Code plugin runs (default: `smem` on `PATH`) |
| `SMEM_SESSION` | Session id |
| `SMEM_KEY_DIR` | Private keys (default: user config dir `smem/keys`) |
| `TYPESAFE_API_KEY` / `OPENROUTER_API_KEY` | Enables the Jev judge |
| `ANTHROPIC_API_KEY` / `ANTHROPIC_AUTH_TOKEN` | Enables the Claude judge |
| `ANTHROPIC_BASE_URL` + `ANTHROPIC_CUSTOM_HEADERS` | Claude judge through a gateway (headers are `Name: value` lines) |
| `SMEM_JUDGE_MODEL` | Claude judge model for this agent, e.g. a gateway-prefixed id |

## Contributing

Contributions are welcome: bug reports, fixes, new checkers or judges,
transports, docs. To get started:

```sh
git clone https://github.com/rahulsub/synapse-mem && cd synapse-mem
make check         # what CI runs: formatting, tidy, vet, golangci-lint, race tests
make build         # bin/smem
```

1. **Open an issue first** for anything bigger than a small fix, so we can
   agree on the approach before you write it.
2. **Fork, branch, and open a pull request** against `main`. Every PR runs
   lint (golangci-lint with gosec and staticcheck), race tests on Linux and
   macOS with a coverage gate, fuzzing, cross-builds, govulncheck, gitleaks,
   dependency review and CodeQL. `ci-ok` must pass.
3. **Keep PRs focused**, one change per PR, with a test that fails without
   your change.
4. **Mind the invariants.** These are the things that are easy to break:
   * event payloads are a wire format, so add fields and never rename them;
   * projections must stay a pure function of the log (`Rebuild` must
     reproduce them);
   * nothing that can run code or redirect credentials may be settable from
     the committed project config;
   * secrets are redacted before anything is signed.

[CONTRIBUTING.md](CONTRIBUTING.md) has the details: layout, testing,
style, and how to add a judge, checker or MCP tool. Report security issues
privately (see [SECURITY.md](SECURITY.md)), not in a public issue.

## License

[MIT](LICENSE)
