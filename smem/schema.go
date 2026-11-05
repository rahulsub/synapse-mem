package smem

// baseSchema holds the tables that are never rebuilt. events is the source of
// truth. meta and key_trust are local policy and are never replicated.
const baseSchema = `
CREATE TABLE IF NOT EXISTS events (
	seq      INTEGER PRIMARY KEY,  -- local insertion order only; not hashed, not replicated
	id       TEXT NOT NULL UNIQUE,
	replica  TEXT NOT NULL,
	rseq     INTEGER NOT NULL,
	at       INTEGER NOT NULL,
	actor    TEXT NOT NULL,
	key_id   TEXT NOT NULL,
	session  TEXT NOT NULL DEFAULT '',
	type     TEXT NOT NULL,
	subject  TEXT NOT NULL DEFAULT '',
	payload  TEXT NOT NULL,
	prev     TEXT NOT NULL,
	hash     TEXT NOT NULL,
	sig      TEXT NOT NULL,
	eff_at   INTEGER,              -- local: the clamped time projections use, if it differs from at
	UNIQUE (replica, rseq)
);
CREATE INDEX IF NOT EXISTS events_order ON events(at, replica, rseq);
CREATE INDEX IF NOT EXISTS events_subject ON events(subject);
CREATE INDEX IF NOT EXISTS events_type ON events(type, session);
CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events
BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;

CREATE TABLE IF NOT EXISTS spool_seen (file TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS key_trust (key_id TEXT PRIMARY KEY, trusted INTEGER NOT NULL, note TEXT NOT NULL DEFAULT '');
`

// viewTables are projections of the event log. Rebuild drops and replays them.
var viewTables = []string{
	"keys", "memories", "memories_fts", "decisions", "decisions_fts", "options",
	"assumptions", "sources", "edges", "accesses", "actions", "approvals", "status_log", "judgments", "judge_runs", "rules", "failures",
}

const viewsSchema = `
CREATE TABLE IF NOT EXISTS keys (
	key_id TEXT PRIMARY KEY, actor TEXT NOT NULL, public_key TEXT NOT NULL,
	replica TEXT NOT NULL, registered_at INTEGER NOT NULL, event TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS memories (
	id TEXT PRIMARY KEY, kind TEXT NOT NULL, content TEXT NOT NULL, scope TEXT NOT NULL DEFAULT '',
	volatility TEXT NOT NULL, confidence0 REAL NOT NULL,
	valid_from INTEGER NOT NULL, valid_to INTEGER, closed_at INTEGER,
	recorded_at INTEGER NOT NULL, retracted_at INTEGER, archived_at INTEGER,
	status TEXT NOT NULL, supersedes TEXT NOT NULL DEFAULT '', superseded_by TEXT NOT NULL DEFAULT '',
	actor TEXT NOT NULL DEFAULT '', session TEXT NOT NULL DEFAULT '', event TEXT NOT NULL
);
CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts USING fts5(id UNINDEXED, content, tokenize='porter unicode61');
CREATE TABLE IF NOT EXISTS decisions (
	id TEXT PRIMARY KEY, question TEXT NOT NULL, choice TEXT NOT NULL, rationale TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL, decided_at INTEGER NOT NULL, actor TEXT NOT NULL DEFAULT '', session TEXT NOT NULL DEFAULT '',
	bead TEXT NOT NULL DEFAULT '', snapshot TEXT NOT NULL DEFAULT '{}',
	outcome TEXT NOT NULL DEFAULT '', outcome_note TEXT NOT NULL DEFAULT '', outcome_at INTEGER,
	supersedes TEXT NOT NULL DEFAULT '', superseded_by TEXT NOT NULL DEFAULT '', event TEXT NOT NULL
);
CREATE VIRTUAL TABLE IF NOT EXISTS decisions_fts USING fts5(id UNINDEXED, question, choice, rationale, tokenize='porter unicode61');
CREATE TABLE IF NOT EXISTS options (
	decision_id TEXT NOT NULL, option TEXT NOT NULL, chosen INTEGER NOT NULL, reason TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS assumptions (
	id TEXT PRIMARY KEY, decision_id TEXT NOT NULL, statement TEXT NOT NULL, check_hint TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL, checked_at INTEGER, note TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS sources (
	id TEXT PRIMARY KEY, kind TEXT NOT NULL, ref TEXT NOT NULL, content_hash TEXT NOT NULL DEFAULT '',
	note TEXT NOT NULL DEFAULT '', captured_at INTEGER NOT NULL
);
-- Edges point from the dependent to what it depends on.
CREATE TABLE IF NOT EXISTS edges (src TEXT NOT NULL, dst TEXT NOT NULL, type TEXT NOT NULL, at INTEGER NOT NULL, event TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS edges_dst ON edges(dst, type);
CREATE INDEX IF NOT EXISTS edges_src ON edges(src, type);
CREATE TABLE IF NOT EXISTS accesses (
	memory_id TEXT NOT NULL, at INTEGER NOT NULL, signal TEXT NOT NULL, weight REAL NOT NULL,
	session TEXT NOT NULL DEFAULT '', event TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS accesses_mem ON accesses(memory_id, at);
CREATE TABLE IF NOT EXISTS actions (
	id TEXT PRIMARY KEY, at INTEGER NOT NULL, actor TEXT NOT NULL DEFAULT '', session TEXT NOT NULL DEFAULT '',
	decision_id TEXT NOT NULL DEFAULT '', bead TEXT NOT NULL DEFAULT '', tool TEXT NOT NULL DEFAULT '',
	summary TEXT NOT NULL DEFAULT '', args_hash TEXT NOT NULL DEFAULT '', result_hash TEXT NOT NULL DEFAULT '',
	commit_sha TEXT NOT NULL DEFAULT '', transcript TEXT NOT NULL DEFAULT '', event TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS actions_decision ON actions(decision_id);
CREATE TABLE IF NOT EXISTS approvals (
	decision_id TEXT NOT NULL, approver TEXT NOT NULL, scope TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '',
	seen TEXT NOT NULL DEFAULT '', at INTEGER NOT NULL, actor TEXT NOT NULL DEFAULT '', event TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS status_log (
	subject TEXT NOT NULL, at INTEGER NOT NULL, status TEXT NOT NULL, cause TEXT NOT NULL DEFAULT '',
	reason TEXT NOT NULL DEFAULT '', actor TEXT NOT NULL DEFAULT '', event TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS status_log_subject ON status_log(subject, at);
CREATE TABLE IF NOT EXISTS judgments (
	id TEXT PRIMARY KEY, subject TEXT NOT NULL, at INTEGER NOT NULL, verdict TEXT NOT NULL,
	confidence REAL NOT NULL, decided_by TEXT NOT NULL, action TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '',
	actor TEXT NOT NULL DEFAULT '', input_hash TEXT NOT NULL DEFAULT '', judge_calls INTEGER NOT NULL DEFAULT 0,
	replica TEXT NOT NULL DEFAULT '', event TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS judgments_subject ON judgments(subject, at);
CREATE TABLE IF NOT EXISTS judge_runs (
	judgment TEXT NOT NULL, judge TEXT NOT NULL, ok INTEGER NOT NULL, status INTEGER NOT NULL DEFAULT 0,
	error TEXT NOT NULL DEFAULT '', at INTEGER NOT NULL, replica TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS judge_runs_judge ON judge_runs(replica, judge, at);
`

// summarySchema holds local caches derived from events: the idle gaps of the
// active decay clock and per-key event counts. Rebuild reconstructs them. They
// are never replicated or signed, and nothing but speed depends on them.
const summarySchema = `
CREATE TABLE IF NOT EXISTS summary_state (
	name    TEXT PRIMARY KEY,            -- 'key_events' or 'idle_gaps/<replica>/<idle_ms>'
	version INTEGER NOT NULL,            -- summaryVersion that built it
	seq     INTEGER NOT NULL DEFAULT 0,  -- key_events: events with seq <= this are counted
	replica TEXT NOT NULL DEFAULT '',    -- idle_gaps: the replica it describes
	idle_ms INTEGER NOT NULL DEFAULT 0,  -- idle_gaps: the threshold it was built with
	rseq    INTEGER NOT NULL DEFAULT 0,  -- idle_gaps: events of replica with rseq <= this are included
	last_at INTEGER NOT NULL DEFAULT 0   -- idle_gaps: the time of the event at rseq
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS summary_idle_gaps (
	replica  TEXT NOT NULL,
	idle_ms  INTEGER NOT NULL,
	ord      INTEGER NOT NULL,           -- position among this state's gaps
	start_at INTEGER NOT NULL,           -- the earlier event's time plus idle_ms
	end_at   INTEGER NOT NULL,           -- the later event's time
	PRIMARY KEY (replica, idle_ms, ord)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS summary_key_events (
	key_id TEXT PRIMARY KEY,
	events INTEGER NOT NULL,             -- every event signed by the key
	regs   INTEGER NOT NULL              -- of which registrations
) WITHOUT ROWID;
`

// migrations bring an existing database up to the current base schema.
// Views need none: a changed view schema is applied by rebuilding.
var migrations = []struct{ table, column, ddl string }{
	{"events", "eff_at", `ALTER TABLE events ADD COLUMN eff_at INTEGER`},
}

// viewsVersion changes whenever viewsSchema or apply changes in a way that
// needs existing projections rebuilt.
const viewsVersion = "5"
