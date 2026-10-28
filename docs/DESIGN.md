# smem: design

smem is an embedded memory for agents. It treats memory as something that
**changes over time and loses value**, records **why** every decision was made,
and keeps a **signed, append-only audit trail** of work and decisions that can
stay local or sync between machines.

It is meant to sit next to [beads](https://github.com/steveyegge/beads), not
replace it. Beads records work: what's ready, what blocks what. smem records
knowledge and reasoning: what we believe, how sure we are, what we decided on
the strength of it, and what happened as a result. The two link by id (a
decision can name a bead; `smem why bd-77` finds it).

## 1. Requirements

| Need | What it means here |
|---|---|
| Time | Separate *when something was true* from *when we learned it*. Never overwrite. |
| Decay | Memories fade from attention unless used, and become less certain unless re-checked. Fading never deletes. |
| Provenance | Every memory and decision says what it came from. When a basis changes, dependents are flagged. |
| Audit | An immutable record of what was done, decided, approved and seen, and by whom. |
| Integrity | Tampering is detectable; events cannot be forged without the author's key. |
| Local and sync | Works offline as a single file; replicas can exchange logs and converge. |
| Embedded | A Go library plus a single-binary CLI; SQLite; no server. |

Non-goals for the core: semantic (embedding) search, automatic extraction of
memories from transcripts, consolidation of episodes into facts. Each has a
place in the design (§9) but none is needed to get the guarantees above.

## 2. Architecture: the log is the database

```
            writes                                   reads
 agent ──▶ Engine.emit ──▶ events (signed, chained) ──▶ apply ──▶ projections
                               ▲      │                            memories, decisions,
                     import ───┘      └──▶ push (feed files)       assumptions, edges,
                     (verify)                                      accesses, actions,
                                                                   approvals, status_log
```

* **Every write appends one or more events.** Nothing else is ever written
  directly; the other tables are *projections* built by `apply(event)`.
* `apply` is a pure function of the event and of earlier state. `smem rebuild`
  drops every projection and replays the log; a test asserts the result is
  byte-for-byte identical.
* Decay, propagation and conflict detection operate on projections. **The log
  itself never decays.** Memories can fade from recall; the record of what
  happened is permanent.

### Event

```
id        evt-<first 16 hex of hash>
replica   which database wrote it
rseq      1, 2, 3 … within that replica
at        recorded time (ms), see §6
actor     who wrote it; key_id names the actor's signing key
session   agent session
type      e.g. memory.asserted, decision.made
subject   the record it is about
payload   JSON, redacted before hashing
prev      hash of this replica's previous event (genesis = 64 zeros)
hash      sha256 of every field above except id
sig       Ed25519 signature over hash by the actor's key
```

Event types: `key.registered`, `memory.{asserted, invalidated, retracted,
suspected, reconfirmed, signal, archived}`, `recall`, `source.captured`,
`decision.{made, outcome, approved, suspected, reaffirmed, reverted}`,
`assumption.{broken, held}`, `action.recorded`. Unknown types are kept and
skipped by `apply`, so an older binary can replay a newer log.

## 3. Time: three clocks

Most memory systems use one "age". That mixes up three things:

| Clock | Question | Changed by |
|---|---|---|
| **Validity** | Is it still true? | Evidence only: `invalidate`, `retract`, `supersede` |
| **Confidence** | How sure are we, given we haven't checked lately? | Time since last verification, by volatility class; contradictions |
| **Salience** | Is it worth bringing up now? | How recently and how often it has been used |

Old is not wrong, and unused is not untrue. Time only lowers salience and
confidence. Validity changes only on evidence.

### Two timelines

Each memory version carries:

* `valid_from` / `valid_to`: when it was true in the world (valid time)
* `recorded_at` / `closed_at` / `retracted_at`: when we learned it, learned it ended, or learned it was never true (recorded time)

A memory is visible to a query *as of* time V, *as known at* time K, when:

```
recorded_at ≤ K
and (retracted_at is null or retracted_at > K)
and valid_from ≤ V
and not (closed_at ≤ K and valid_to ≤ V)      -- closing only counts once we knew
```

So `recall --as-of 2026-03-01 --known-at 2026-03-02` answers "what did we
believe on March 2nd about how things were on March 1st", which is the
question an audit asks about a past decision.

Memory versions are immutable: a changed fact is a **new memory that
supersedes** the old one. The old one gets `valid_to` = the new one's
`valid_from`. A memory id therefore *is* a version, which is why a decision's
snapshot can just list ids.

* **Invalidate**: it was true, the world changed. (`valid_to` set.)
* **Retract**: it was never true; the belief was wrong. (`retracted_at` set; queries known after that moment don't see it at all.)
* **Supersede**: there is a newer version.

## 4. Decay

Scores are computed **when a memory is recalled**, from an access log, not
stored and updated by a background job.

```
score      = relevance × salience × confidence
relevance  = bm25(query) normalized to (0,1]; 1 when there is no query
salience   = σ(B + 2),  B = ln Σⱼ wⱼ · tⱼ^(−d_kind)        -- ACT-R base-level activation
confidence = c₀ · ½^(Δt_verified / half_life[volatility]) · ½^(contradictions) · (½ if suspect)
```

* `tⱼ` is hours since access j (min 1 minute). ACT-R gives recency,
  frequency and the spacing effect for free.
* Access weights `wⱼ`: asserted 1, retrieved 0.5, used 1, cited by a decision
  1.5, confirmed by a successful outcome 2, reconfirmed 1. A contradiction
  doesn't add to activation; it halves confidence.
* Decay exponent by kind: episode 0.8, fact 0.5, insight 0.4, procedure 0.3,
  preference 0.3.
* Confidence half-life by volatility: volatile 1 day, normal 30 days, stable
  1 year, permanent never. Defaults: facts and insights normal; episodes,
  procedures and preferences stable.

Reference points: one access an hour ago gives salience ≈ 0.88; one access a
year ago ≈ 0.07 for a fact, ≈ 0.3 for a preference.

**Tiers.** Hot memories are injected at session start (`smem context`, within
a character budget). Warm ones are found by `recall`. Cold ones are archived
by `sweep` (salience below 0.15 and untouched for 30 days): they leave default
recall but stay in the log and are returned with `--archived`. Nothing is
deleted. Anything a decision cites stays reachable through `why`.

Historical queries (`--known-at`) compute salience and confidence from
accesses up to that moment, so you can replay what an agent would have
recalled then.

**Active clock.** Salience decays on the agent's active time by default
(`decay.clock`). Each stretch with no events from this replica counts as at
most `decay.idle_after` (24h), including the current one. An agent that is
off for two weeks comes back remembering what it knew. On the wall clock it
would come back nearly empty. Confidence still decays on real time: whether
a fact is still true doesn't depend on whether the agent was running. The
idle stretches are cached and extended as new events arrive.

**Being shown is not being used.** Session-start injection is logged (the
audit trail shows what the agent was given) but doesn't count as an access,
unless `context.reinforce` is set. Otherwise memories that are injected
would stay salient just by being injected. An agent that injects context
another way logs it with `recall --injected`: the decision snapshot sees it,
salience doesn't.

**Contradictions are answered by verification.** Only contradictions since
the memory was last asserted, reconfirmed or confirmed reduce confidence.

## 5. Provenance and propagation

### The graph

Edges point from the dependent to what it depends on:

```
decision ──used──────────▶ memory (version)
decision ──evidenced_by──▶ source (url, commit, bead, file, transcript)
decision ──supersedes────▶ decision
memory   ──derived_from──▶ memory | decision | source
memory   ──supersedes────▶ memory
assumption ∈ decision     (statement + check hint)
action   ──▶ decision     (via decision_id)
```

The vocabulary follows W3C PROV loosely: memories and sources are entities;
decisions and actions are activities; actors are agents.

### Truth maintenance

When a basis changes (a memory is invalidated, retracted or superseded; an
assumption is broken; a decision is reverted or superseded), smem walks the
graph to the records that depend on it and emits `*.suspected` events, each
naming its **cause** and the **root** of the chain. This is a
justification-based truth maintenance system (Doyle, 1979), made practical
because agents can record the justifications as they work.

* **Depth.** Only direct dependents are flagged automatically
  (`PropagationDepth = 1`). Further downstream records appear in
  `smem review` as **at risk**. One bad fact can't wipe out confidence across
  the whole store, and a person or agent decides how far the doubt should go.
* Only *active* records are flagged, so propagating the same cause twice is a
  no-op. That makes it safe to re-run after a sync (§7).
* Suspect decisions are cleared with `reaffirm` (it still stands) or `revert`.
  Suspect memories with `reconfirm` or `invalidate`.
* **Decisions decay differently.** Their salience fades, but their authority
  doesn't. A decision stays binding until superseded, reverted, or its basis
  breaks.
* **Outcomes feed back.** A `success` outcome confirms every memory the
  decision used (weight 2). A `failure` does not weaken them automatically,
  because the reasoning may have been at fault rather than the facts.

## 6. Audit trail

### What a decision records

| Field | Purpose |
|---|---|
| question, choice, rationale | The decision and the agent's stated reasons |
| rejected options + reasons | Usually the most valuable part later |
| assumptions + check hints | Lets a decision be flagged when an assumption breaks |
| used | The memory versions relied on (these drive propagation) |
| evidence | Sources; free references are captured as sources automatically |
| snapshot | The memories in view (by default the session's last recall), model, prompt hash, skills |
| bead | Link to the work item |
| approvals | Who signed off, and the hash of the decision event they saw |
| actions | Work done under it (tool calls, commits) |
| outcome | Recorded later |
| history | Every status change with its cause |
| signers | Actor and key of every event about the decision |

**Stated vs observed.** An LLM's rationale is an explanation written after the
fact, not proof of what caused the action. smem stores both the stated
rationale and the observed facts: what was recalled (recall events) and what
was done (hook-captured actions). When they disagree, that is worth seeing.

### Capture without relying on discipline

* **Actions**: the Claude Code `PostToolUse` hook (`smem hook post-tool-use`)
  captures every mutating tool call: a redacted summary, hashes of input and
  output, the transcript path, the subagent id, and the commit sha if the
  call was a `git commit`.
  * By default it writes this to `.smem/spool/` and exits without touching
    the database, so a busy store can never make the hook time out. The next
    writer records spooled calls in one transaction: a CLI command, an MCP
    call, or a session start. Each file is marked done in that same
    transaction, so a crash can't record it twice.
  * The hook finds the store from the `cwd` in its input, not from wherever
    the hook process starts.
  * Read-only tools, smem's own MCP tools and `hooks.skip_tools` are not
    recorded.
* **Linking actions to decisions** is inference from timing, and is
  recorded as such (`linked_by`). By default (`hooks.link_decisions:
  unambiguous`), a call is linked to the session's latest decision only if
  no other decision was made in that session within `hooks.link_window`.
  Parallel subagents making decisions therefore don't get each other's
  actions. `smem action --decision` and `Decision:` trailers are exact.
* **Sessions** are tied to processes. Claude Code doesn't tell an MCP
  server which session it serves, but the server and the hooks share an
  ancestor, the Claude Code process.
  * The session-start hook records the session id under each ancestor's pid
    in `.smem/sessions/`.
  * The MCP server looks up its own ancestors, nearest first.
  * Two sessions in one directory each find their own, and records of exited
    processes are pruned.
* **Context**: the `SessionStart` hook (`smem hook session-start`) injects
  memories within `context.budget`, filtered by `scopes.read` and
  `context.kinds`, for the start sources in `context.on` (startup and clear
  by default, not resume or compact). It notes when synced events are
  quarantined.
* **Decisions**: the agent calls `smem decide`. (Extracting decisions it
  didn't record is future work, §9.)
* **Commits**: `smem trailer <dec>` prints `Decision: dec-…` for the commit
  message. `smem why <sha>` follows both recorded actions and trailers, so
  `git blame` → commit → decision → rationale, rejected options, and what the
  agent knew.

### Questions it answers

* `smem why <sha|dec|mem|asm|act|src|bead>`: why is this the way it is?
* `smem recall --as-of T --known-at T`: what did we believe then?
* `smem review`: which decisions rest on something that has changed?
* `smem log --subject <id>`: every event about a record, with signer.
* `smem verify`: has anything been altered?

## 7. Integrity: signing

* Each actor has an **Ed25519 key**, generated on first write and stored
  outside the database (`$SMEM_KEY_DIR`, default the user config dir, mode
  0600). The first event an actor writes in a replica is a self-signed
  `key.registered` with the public key; `key_id` is a fingerprint of it.
* Every event is hashed (covering its replica, position, previous hash, time,
  actor, key, type, subject and payload) and signed.
* SQLite triggers refuse `UPDATE` and `DELETE` on `events`.
* **Redaction happens before hashing.** An append-only log can't be cleaned
  up later, so secrets have to be stopped on the way in (see below).

### Credentials

The judge keys (`TYPESAFE_API_KEY`, `OPENROUTER_API_KEY`,
`ANTHROPIC_API_KEY`) are read from the environment when the store is
configured and held only in memory. They are never written to the database,
`.smem/config.json` or any output, and errors from judges never include
response bodies.

Everything else that could carry a secret goes through `Redact`:

| Path | What is redacted |
|---|---|
| Every event payload | each string value, after decoding, before hashing and signing |
| Fact-check evidence | file and commit text, before it is sent to a judge |
| Checker errors | the checker's stderr |

`Redact` removes two kinds of thing:

1. **The exact values of credential environment variables**, in any format:
   the judge keys plus any variable whose name looks like a secret
   (`*TOKEN*`, `*SECRET*`, `*PASSWORD*`, `*API_KEY*`, `*CREDENTIAL*`,
   `*AUTH*`) with a value of 12 or more characters. A key in a format no
   pattern knows is still caught if it is in the agent's environment.
2. **Common secret shapes**: Anthropic/OpenAI-style keys, AWS, GitHub and
   Slack tokens, JWTs, PEM private keys, `Bearer`/`Basic` credentials,
   `Authorization:`/`x-api-key:` headers, `user:password@` in URLs,
   `NAME=value` / `"name": "value"` for secret-like names, and
   `--password value`-style flags.

Command checkers run with the judge keys removed from their environment. A
checker is local code you configured, but it has no need for smem's model
credentials.

Tool calls captured by the hook are stored as a redacted one-line summary and
hashes of the arguments and result, never the full arguments or output.

**Limits.** Pattern matching is best effort: a secret in an unknown format
that is not in the environment (say, pasted into a memory by hand) can get
through. If one does, it is in the signed log for good: rotate the secret.
`TestCredentialsNeverStored` plants keys in the environment, drives every
write path and a hostile checker, and scans the database files, the export
and what the judge received.

`smem verify` checks for every replica: contiguous `rseq`, each `prev` equal
to the previous hash, each hash equal to its recomputed content, each
signature valid for the registered key, and that the key belongs to the
claimed actor.

**What this does and doesn't guarantee.** Nothing can make a local file
impossible to modify. The guarantees are:

1. **Modification is detected.** Changing, inserting, removing or reordering
   an event breaks the hash or the chain.
2. **Forgery needs the key.** Re-signing a modified event with another key
   fails verification (the key is bound to the actor by its registration).
3. **Rewriting your own history is visible to others.** Once events have been
   synced, every peer holds them; a rewritten feed is refused as a fork.
   `smem heads` prints the latest hash per replica. Publishing heads somewhere
   append-only (a commit message, a chat channel) anchors the log even against
   someone who controls every key on the machine.

**Trust** is local policy, like `known_hosts`. Keys created locally are
trusted. Keys arriving by sync are untrusted until `smem keys trust
<key-id>`, or until they're listed in `trust.keys` in the local config.
Trust is not an event and is never synced.

**Untrusted events are quarantined, not applied.** Anyone who can write to
a shared feed directory can produce validly signed events with a key of
their own. So events from an untrusted key are stored and verified (chains
stay intact and nothing is lost), but they are not projected. They never
reach recall, session context, review or propagation. Changing trust
replays the log, so trusting a key brings its events in, and distrusting
one removes them from every view. `smem doctor`, `smem stats` and the
session context report how many events are held back.

**Identity is not silently replaced.** If an actor that already signs this
replica has no private key in the key directory, writes are refused with
an explanation. The usual cause is a key directory on ephemeral storage, such
as an agent's `$HOME` that is lost on restart. Minting a new key would split
the actor's history across identities. `keys.allow_new` starts a new key
deliberately. `smem doctor` warns when the key directory is under a
temporary path.

## 8. Local and sync

### Local mode

One SQLite file (`.smem/smem.db`, found by walking up from the current
directory, or `$SMEM_DB`). Several agents on one machine share it; SQLite
serializes writes. Every event is still signed and chained.

### Sync mode: one feed per replica

A single global hash chain can't survive two machines appending at once.
Instead each replica (database) owns an append-only **feed**. Replicas
exchange feeds; nobody ever writes into someone else's feed. This is the same
shape as Secure Scuttlebutt and Hypercore.

**Order.** The merged log is ordered by `(at, replica, rseq)`. When writing,
`at` is set to `max(clock, newest event seen + 1 ms)`, a hybrid logical
clock. Anything causally after an event therefore sorts after it, whatever the
machines' clocks say. Queries treat "now" as the later of the clock and the
newest event.

**Import** (`Engine.Import`), for each incoming feed:

1. Skip events we already have, checking the hash matches; a different event
   at a known position is a **fork** and the feed is refused from there.
2. Require the next `rseq`, the right `prev`, a known key bound to the
   claimed actor, a correct hash and a valid signature. Stop at the first
   failure: nothing after a bad event is trusted.
3. **Bound time.**
   * An event dated more than `sync.max_future_skew` (5 min) ahead is
     refused until the clocks agree. Accepting it would drag every later
     local timestamp forward.
   * A feed whose time runs backwards is refused.
   * An event older than `sync.max_backdate` (30 days) is kept exactly as
     signed, but projected at the clamped time (stored locally as `eff_at`).
     A backdated event therefore can't make as-of queries say something was
     known earlier than it arrived.
4. **Quarantine** events from untrusted keys (§7).
5. If an accepted event sorts before what is already projected *and* is
   **order-sensitive** (a status change, or a supersede where the first
   successor wins), **replay** the projections in order. Inserts and access
   records commute, so they are applied directly. In practice most late
   arrivals are recalls and new memories, so a pull rarely replays the log.
6. **Propagate locally.** The remote writer couldn't see our dependents (a
   decision made here using a memory invalidated there), so invalidations
   arriving by sync are propagated again. Records already flagged are left
   alone.

**Conflicts.** If two replicas supersede the same memory or decision
independently, the first in log order becomes `superseded_by`. Both successors
stay live and `smem review` lists the fork. Resolve it by superseding one.
Status changes are idempotent (only active records become suspect), so
duplicate flags from two replicas do no harm.

**Convergence.** Replicas holding the same events produce identical
projections after a rebuild; a test checks this across two replicas.

**Transport.** The first remote is a **directory**: `feeds/<replica>.jsonl`,
one file per replica, appended only by its owner. That works over a shared
disk, Dropbox or a git repo (commit the directory). The directory is
untrusted: every event is verified on import. `push` refuses if the remote
copy of our own feed doesn't match the local log. Other transports (S3, HTTP,
beads/Dolt) only need "read all feeds" and "append to my feed".

**Robustness.**
* **Torn writes:** a push writes all new lines in one write and syncs. A
  reader skips a torn last line, and the feed's owner truncates it before
  its next push. A feed that is broken mid-file is reported, and the other
  feeds still import.
* **New stores:** processes that create a store at the same moment agree on
  one replica id (insert-if-absent, with a retry while the database is being
  created).
* **Copies:** the store records the identity of its database file (device
  and inode). A restored backup or a copy to another machine sees a
  different file and continues as a new replica. Continuing under the old
  id would fork that replica's chain for good.

**Pull-only remotes** (`smem remote add team <dir> --pull-only`) are read
but never written. Combined with trust, this is how agents share memory
read-only: a curator publishes a feed, agents pull it and trust only the
curator's key, and each agent's own feed stays its own. `scopes.read`
decides what each agent sees.

## 9. Fact-checking and judges

Confidence decays until something re-checks a memory. Fact-checking does that
check automatically, cheapest step first:

```
memory ──▶ gather evidence ──▶ checkers ──▶ Jev ──▶ Claude (Haiku 5.5) ──▶ review
           linked files,        user-written   fast,     only when Jev is unsure,
           commits, similar     code; first    calibrated unavailable, or absent
           memories             verdict wins   probabilities
```

**Typed questions** (`judge` package). Every judgment is a typed question:
`Choice` (labels, a probability per label), `Probability` (P(yes)), or
`Score` (ordered rubric). Any judge's answer can therefore be checked
mechanically: is the choice one of the labels, do the probabilities sum to 1.
A malformed answer is an error, never a default verdict. A fact-check asks two
questions: `relation` (supports / contradicts / says_nothing) and
`same_subject` (P(the evidence is about the same thing)). A contradiction only
counts when `same_subject ≥ 0.5`.

**Checkers** are user-written functions that run before any model:

* Go: implement `smem.Checker`, or wrap a function with `smem.CheckFunc`, and
  set `e.Checkers`.
* Any language: a command in the **local** config (never `.smem/config.json`,
  which may be committed, and never synced data: either would let someone
  else run code on your machine). It gets the claim (memory plus evidence)
  as JSON on stdin and prints `{"verdict": {...}}`, `{"evidence": [...]}`, or
  nothing to abstain. It runs with a minimal environment (`PATH`, `HOME`,
  `USER`, `LANG`, `LC_ALL`, `TZ`, `TMPDIR`) plus the variables its config
  names. smem's API keys are never passed.

A checker's verdict counts as one check; it can also contribute evidence for
the judges.

**Evidence** is limited to the project. A file source must resolve, symlinks
included, to a regular file inside the directory holding `.smem`, must match
`factcheck.evidence.allow`, and must not match the deny list: `.git`,
`.smem`, `.beads`, `.env*`, keys and certificates, `.ssh`, `.aws`, `.netrc`,
`.npmrc`, credential files, `*secret*` and Terraform state, plus anything
configured. So a synced source pointing at `/proc/self/environ` or
`../../.aws/credentials` reads nothing. Commit sources must be plain hashes,
because a synced ref like `--output=…` would otherwise reach `git show` as an
option.

**Judges.**
* **Jev** is enabled by `TYPESAFE_API_KEY` (or `OPENROUTER_API_KEY`).
* **Claude** is enabled by `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN`.
  The default is Haiku 5.5 at low effort with structured outputs. The model,
  effort and token limit are configurable, and `ANTHROPIC_BASE_URL` or
  `endpoints.claude` points it at a gateway.
* **Settling and escalation.** A judge's answer is confident at
  `auto_accept` (0.8); otherwise the next judge is asked.
* **Errors.** A provider error is recorded, and the next stage is asked.
  `smem judges --ping` and `smem doctor --ping` surface errors that would
  otherwise only appear as a fallback.

**Agreement.** Acting on a memory needs `factcheck.min_agreeing` (default 2)
independent checks that agree, where each checker verdict and each confident
judge counts once.
* With the default, no single judge can reconfirm a memory or mark it
  suspect. Jev is weak on dates and numbers, so a confident Jev answer still
  leads to Claude being asked for a second opinion.
* A checker plus one judge counts as two.
* Checks that disagree, or too few checks, send the memory to review.

**Cost.** A judgment is cached by the hash of the claim and its evidence,
for `cache_ttl` (24h). `daily_budget` caps judge calls per replica per 24
hours; over budget, checks use checkers only and say so. In the MCP server
a fact-check runs in the background on a second database handle, so other
calls are never blocked behind it.

**Calibration.** Jev returns probabilities from its output distribution;
Claude reports its own confidence. Results carry `calibrated` so thresholds can
be tuned per judge. Judgments plus later outcomes give the data to fit them.

**Actions are asymmetric.** With `apply`:

| Verdict | Action |
|---|---|
| supported, settled, ≥ `auto_reconfirm` (0.9) | reconfirm: resets the confidence clock |
| contradicted, settled, same subject | mark **suspect** (never invalidate); dependents show as at-risk |
| too few agreeing checks, or checks disagree | review queue (`smem review`) |
| insufficient | nothing |

Every check is a signed `judgment.recorded` event: verdict, who decided,
each judge's answers, model, calibration, latency, usage, and evidence by
reference and hash (not content). Any resulting suspicion names the judgment
as its cause, so `smem why mem-…` shows exactly which judge said what.

**What gets checked.** `smem factcheck --due` picks facts and insights whose
confidence has decayed below a threshold, most salient first, skipping any
checked in the last day. Preferences and episodes aren't fact-checked.
Evidence and the claim are redacted before leaving the machine.

## 9a. Rules governance

Agents create rules for themselves (in `CLAUDE.md`, `.claude/rules`, memory)
with no record of why. Over time nobody can tell which rules still matter,
which contradict each other, and which were one-off reactions. smem treats a
rule as a record with a **reason**, behind an admission gate.

**Records.**
* `failure.recorded`: a failure with a label (`wrong-port`,
  `migration-left-half-applied`), a summary and a reference.
* `rule.proposed` and `rule.admitted`, then `rule.rejected`,
  `rule.retired`, `rule.suspected`, `rule.reaffirmed` and `rule.violated`.
  Rules are projections like everything else, so they replay, sync, verify
  and can be traced with `why`.

**The gate.** A proposal becomes active only if all of these hold:
1. **A reason holds up.**
   * *requested:* who asked, and their words.
   * *incident:* `min_failures` with the rule's label within
     `failure_window`, plus `enforced_by` if `require_enforcement` is set.
   * *decision:* an active decision.
   * *approved:* a named person.
   * *merge:* every rule merged was active.
2. **It isn't a near-duplicate** of an active rule in its scope (word
   overlap ≥ `duplicate_at`).
3. **The scope is under `max_active`.**

A proposal that fails is kept with the reason it was held. It's promoted
automatically when enough labeled failures arrive (`auto_promote`), or by a
person (`rules approve --by`).

**Propagation.** A rule justified by a decision has a `justified_by` edge to
it. Reverting the decision, or the decision becoming suspect, flags the rule
suspect through the same propagation as memories and decisions, and
`review` lists it.

**Rationalize** reviews the whole set. It doesn't change anything; it lists:
* duplicates, by word overlap. With `--judges`, it also asks a typed
  question (`same_rule`, a probability) about the 15 most similar pairs that
  share at least one word, which catches paraphrases;
* held proposals, and those that would now pass;
* suspect rules;
* **ineffective** rules: failures with their label after admission;
* violated rules;
* **stale** rules: no activity within `stale_after`;
* scopes over the cap.

`--import` reads existing `CLAUDE.md` and rule files: bullets, with their
continuation lines, and imperative sentences, skipping code blocks and
smem's own block. Each becomes a held proposal citing its file and line.

**Render** writes active rules, each with its id and basis, between
`<!-- smem:rules:start -->` and `<!-- smem:rules:end -->` in `rules.file`.
Everything outside the block is left alone. `--check` fails if the file is
out of date, for CI. `rules.in_context` also injects them at session start.

## 10. Performance

Measured on an M5 Ultra (`SMEM_SCALE=1 go test -run TestScale ./smem/`), with
every write going through signing, chaining and projection:

| Memories | Write | Recall (query) | Session context | Verify | Sync import | DB |
|---|---|---|---|---|---|---|
| 10,000 | 0.24 ms | 3 ms | 46 ms | 0.26 s | ~25k events/s | 16 MB |
| 50,000 | 0.28 ms | 11 ms | 57 ms | 1.3 s | ~25k events/s | 63 MB |

The benchmark's vocabulary is deliberately small, so most memories match most
queries; real text is easier. Verification is linear (≈26 µs/event) and is an
audit operation, not a hot path. A fact-check is dominated by the judge's
network latency, so checks run concurrently (`--parallel`, default 4); only
the final write takes the database lock.

Known costs as the store grows:

* **Recall logging.** Every recall is an event and adds access rows. That's
  what makes the audit trail show what an agent saw, and what drives
  reinforcement. Repeats within `recall.dedupe_window` aren't logged again,
  and session-start injection adds no access rows. The log still grows
  without bound: an append-only signed log has no deletion. The planned
  answer is a signed checkpoint (a snapshot of the projections plus the
  heads it covers) that lets old segments be archived off the hot database
  while staying verifiable. It's not built yet; `smem stats` shows the
  growth rate.
* Session context scores every memory (linear). Past ~100k memories,
  pre-filter candidates by a maintained last-access column.
* Sync re-reads whole feed files; track per-feed offsets for large logs.
* **Writes are serialized:** one SQLite file per replica (~4k writes/s).
  Hooks never wait on that: post-tool-use spools, and session-start waits at
  most `hooks.lock_timeout` (2s). Many agents on one machine can share a
  store; a fleet should use one replica per agent and sync.
* **Late events:** a sync import replays the log only when a late event is
  order-sensitive (§8). Recalls and new memories arriving late are applied
  directly.

## 11. Where to go next

1. **Rules: closing the loop.** Detect rule violations from tool calls (a
   rule can name a check), and link each failure to the session that caused
   it.
2. **Semantic recall.** Add embeddings (sqlite-vec) as another relevance
   signal next to bm25; `auth` should find "authentication".
3. **Extraction and consolidation.** A pass at session end proposes memories
   and decisions from the transcript, as proposals the agent or user confirms.
   Repeated episodes become facts or procedures, linked by `derived_from`.
4. **Assumption checking** through the same checker/judge cascade:
   assumptions are claims too.
5. **Key rotation and revocation** as signed events.
6. **Log checkpoints** so old segments can be archived (§10).
7. **Evaluation.** Replay past sessions with `--known-at` and measure whether
   recall surfaced what was later cited.
8. **Beads integration.** Write `bd provenance` entries for decisions that
   name a bead, and file suspect decisions as beads so they show up in
   `bd ready`.
9. **Feed offsets.** Pull currently re-reads whole feed files; track offsets
   per feed for large logs.

## 12. Code map

| File | Contents |
|---|---|
| `smem/event.go` | Event, hashing, signing, ordering |
| `smem/keys.go` | Key storage, registration, trust |
| `smem/engine.go` | Open, write transactions, emit |
| `smem/apply.go` | Event payloads and the projection function |
| `smem/memory.go` | Memories, invalidation, propagation |
| `smem/decision.go` | Decisions, assumptions, outcomes, approvals, actions |
| `smem/recall.go` | Scoring, two-timeline queries, context, sweep |
| `smem/review.go` | Suspect, at-risk, conflicts, untrusted keys |
| `smem/why.go` | Traces and their text rendering |
| `smem/verify.go` | Verification, heads, rebuild |
| `smem/sync.go` | Import, export, directory remote |
| `smem/hook.go` | Hook capture, spool, decision linking, process-tied sessions |
| `smem/doctor.go` | `doctor`, `stats`, judge ping |
| `smem/rules.go` | Failures, rules, the admission gate, rationalize, import, render |
| `smem/fileid_*.go` | Database file identity, for detecting copies |
| `smem/redact.go` | Secret redaction, checker environment |
| `smem/factcheck.go` | Checkers, evidence gathering, fact-check cascade, judgments |
| `smem/config.go` | Project and local config, policies, judges and checkers from config and environment |
| `judge/` | Typed questions, cascade, Jev and Claude judges |
| `mcp/` | MCP server (JSON-RPC over stdio) and its tools |
| `cmd/smem` | CLI |
| `plugin/` | Claude Code plugin: MCP server, hooks, skill |

## 13. Packaging

One codebase ships four ways:

| Form | For | How |
|---|---|---|
| Go library | Go agents | `go get github.com/rahulsub/synapse-mem/smem`; `smem.Open`, then `Configure` |
| `smem` binary | shells, scripts, VMs | static, no cgo: darwin/linux × arm64/amd64 from goreleaser on a `v*` tag |
| `smem mcp` | any MCP-capable agent | stdio server with eleven tools; one config entry |
| Claude Code plugin | Claude Code | `plugin/`: the MCP server, both hooks and a usage skill |

The MCP server handles one request at a time (the store has one writer). It
signs as the connecting client (`clientInfo.name`, e.g. `claude-code`) unless
`SMEM_ACTOR` is set, so the hook's records and the server's share a key. It
files records under the session the session-start hook last wrote to
`.smem/session`, so a decision made over MCP links to the tool calls the hook
records afterwards. With two sessions in one directory, the newest wins.

`smem mcp --init` creates `.smem/` in the working directory if no store is
found above it. `Open` writes `.smem/.gitignore` so the store, WAL and session
file stay out of git while `config.json` can be committed.

