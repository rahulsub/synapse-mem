# Contributing to synapse-mem

Thanks for helping. This guide covers what you need to make a change that
can be merged quickly.

## Setup

You need Go 1.27 or later. There is no cgo and nothing else to install:
SQLite is pure Go, and the tests need no network, services or API keys.

```sh
git clone https://github.com/rahulsub/synapse-mem && cd synapse-mem
make test    # go vet ./... and go test -race ./...
make build   # bin/smem
```

`SMEM_SCALE=1 go test -run TestScale ./smem/` runs the scale benchmark
(slow; not part of CI).

## Workflow

1. For anything beyond a small fix, open an issue describing the problem and
   the approach first.
2. Fork the repo and branch from `main`.
3. Make the change with tests. A bug fix should come with a test that fails
   without it.
4. Run `make check` (formatting, tidy, vet, golangci-lint and the race-enabled
   tests: what CI runs, apart from fuzzing and the security scans).
5. Open a pull request. Fill in the template, and link the issue. CI must
   pass.

Keep PRs to one change. Refactors and behavior changes go in separate PRs.

## What CI checks

Every pull request runs:

| Check | What it catches |
|---|---|
| gofmt, `go mod tidy`, `go vet` | formatting, module drift, suspicious code |
| golangci-lint (`.golangci.yml`) | staticcheck, gosec, errcheck, errorlint, nilerr, rowserrcheck and more; every `//nolint` needs a reason |
| tests on Linux and macOS | `-race`, shuffled order, coverage at or above 60% |
| fuzzing | 30 seconds each on the parsers of untrusted input |
| cross-compile + goreleaser check | all four release platforms still build |
| govulncheck | known vulnerabilities in code paths we actually call |
| gitleaks | secrets in any commit of the PR (`.gitleaks.toml` allowlists the fake ones in redaction tests) |
| dependency review | new dependencies with known vulnerabilities or copyleft licenses |
| CodeQL | security analysis of the Go code and of the workflows |
| actionlint, shellcheck | the workflows and shell scripts |

`ci-ok` is the required check: it passes only when every job does.
Dependabot opens weekly grouped updates for Go modules and Actions, which go
through the same checks. Actions are pinned to commit hashes.

## Layout

| Path | What |
|---|---|
| `smem/` | The engine: events, projections, recall, decisions, sync, fact-checking, rules, hooks, config |
| `judge/` | Typed questions, the judge cascade, the Jev and Claude judges, retries |
| `mcp/` | The MCP server and its tools |
| `cmd/smem/` | The CLI |
| `plugin/` | The Claude Code plugin (MCP server, hooks, skill) |
| `docs/DESIGN.md` | How it works and why; read the relevant section before changing behavior |
| `docs/CONFIG.md` | Every configuration setting |

## Invariants

These hold everywhere, and reviews check them:

- **The log is the database.** Every state change is a signed event,
  appended. Other tables are projections built by `apply()`. They must be a
  pure function of the events, so `Rebuild()` reproduces them exactly
  (`dumpViews` in the tests checks this). Don't read local config inside
  `apply`: put the value in the event instead, as `confirm_boost` does.
- **Event payloads are a wire format.** Old logs must still replay. Add
  fields with `omitempty`, and never rename or repurpose one. Unknown event
  types must be skipped, not rejected.
- **Order matters for some events.** If a new event type changes state that
  another event can also change, mark it in `orderSensitive`.
- **Security boundaries.**
  - Anything that runs code, sends data elsewhere, or decides trust is
    local-config only (`localOnly` in `config.go`).
  - Synced data is untrusted. Never execute it, and never pass it to a shell
    or to git unvalidated.
  - Secrets are redacted before hashing (`Redactor`), and API keys never
    reach the database, the config, logs or checkers.
- **Fail loudly.** A judge, hook or sync problem must be visible in `review`,
  `doctor` or the command output, not silently ignored.
- **Configuration over code** for anything that differs between teams. A new
  setting goes in the right policy struct with a default, and in
  `docs/CONFIG.md`.

## Style

- Standard Go: `gofmt`, `go vet`, no new linters needed.
- Match the surrounding code. Comments explain why, not what.
- Errors say what to do next when there is something to do ("set
  SMEM_KEY_DIR …").
- Tests are behavior-level and named for the behavior
  (`TestQuarantineUntilTrusted`). Use the helpers in `smem_test.go`
  (`newEngine`, `start()` for a controllable clock, `must`).
- New dependencies need a good reason. The module currently depends only on
  the SQLite driver, the Anthropic SDK and the Snowball English stopword list
  (MIT, no dependencies of its own), which is the canonical list for the Porter
  stemmer family the index uses.

## Common changes

- **A judge:** implement `judge.Judge` (`Name`, `Ask`), validate with
  `judge.Check`, use `Retry` and `Limiter` for HTTP, and return
  `*judge.HTTPError` so failures show their status. Wire it up in
  `configureJudges`.
- **A checker:** implement `smem.Checker`, or use `CheckFunc`. Command
  checkers need no code: they're configured in the local config.
- **An MCP tool:** add an entry to `tools` in `mcp/tools.go`, with a schema
  whose required fields are declared properties (a test checks this). Mark
  it `slow` if it waits on the network.
- **A CLI command:** add it to the `commands` map and to `usage`. A test
  fails if the two disagree.
- **A sync transport:** it needs "read all feeds" and "append to my feed".
  See `DirRemote`.

## Releases

Maintainers tag `vX.Y.Z` on `main`; the release workflow builds and
publishes binaries with goreleaser.

## License

By contributing, you agree that your contributions are licensed under the
MIT License.
