// Package smem is an embedded agent memory with temporal decay, decision
// provenance and a signed, append-only audit log that can sync between
// replicas.
//
// Every write appends a signed event to the log; all other tables are
// projections of that log and can be rebuilt from it at any time.
package smem

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/rahulsub/synapse-mem/judge"
)

// Engine is a handle on one smem database (one replica).
type Engine struct {
	db      *sql.DB
	path    string
	replica string

	// Now is the clock; tests replace it.
	Now func() time.Time
	// Actor names who is writing. Each actor signs with its own key.
	Actor string
	// Session groups events from one agent session.
	Session string
	// KeyDir holds private signing keys.
	KeyDir string
	// PropagationDepth is how many hops an invalidation marks dependents
	// suspect automatically. Anything further is reported as at-risk by Review.
	PropagationDepth int
	// Checkers run first in a fact-check, in order; Judges are asked when
	// no checker decides. See Configure.
	Checkers        []Checker
	Judges          judge.Cascade
	FactCheckPolicy FactCheckPolicy
	// Policy holds the behavior settings from the config files.
	Policy Policy
	// AllowNewKey lets an actor that already signs this store start a new
	// key when its private key is missing. Off by default: a missing key
	// usually means the key directory was lost (an ephemeral $HOME), and
	// silently becoming someone new would split the actor's history.
	AllowNewKey bool

	opts     OpenOptions
	redactor *Redactor
	keys     map[string]ed25519.PrivateKey
	gaps     gapCache
	beadRe   *regexp.Regexp
}

// OpenOptions tune how a database is opened.
type OpenOptions struct {
	// BusyTimeout is how long to wait for another process's write lock.
	// Default 10s; hooks use less so they never outlast their own timeout.
	BusyTimeout time.Duration
}

type execer interface {
	Exec(string, ...any) (sql.Result, error)
}

// Open opens or creates the database at path.
func Open(path string) (*Engine, error) { return OpenWith(path, OpenOptions{}) }

// OpenWith opens or creates the database at path with options.
func OpenWith(path string, opts OpenOptions) (*Engine, error) {
	if opts.BusyTimeout <= 0 {
		opts.BusyTimeout = 10 * time.Second
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // a project directory; the store file inside is what matters
		return nil, err
	}
	// In a project's .smem directory, keep the store out of git; the config
	// (checkers, judge settings) can still be committed.
	if filepath.Base(dir) == ".smem" {
		ignore := filepath.Join(dir, ".gitignore")
		if _, err := os.Stat(ignore); errors.Is(err, os.ErrNotExist) {
			// Best effort, and readable like any other committed file.
			_ = os.WriteFile(ignore, []byte("*\n!.gitignore\n!config.json\n"), 0o644) //nolint:gosec // a .gitignore is meant to be readable
		}
	}
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(%d)&_pragma=journal_mode(WAL)&_txlock=immediate", path, opts.BusyTimeout.Milliseconds())
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// One connection: writes are serialized and a transaction never waits on
	// a second connection from the same process.
	db.SetMaxOpenConns(1)
	e := &Engine{
		db: db, path: path, Now: time.Now, Actor: defaultActor(""), Session: os.Getenv("SMEM_SESSION"),
		KeyDir: DefaultKeyDir(), PropagationDepth: 1, keys: map[string]ed25519.PrivateKey{},
		Policy: DefaultPolicy(), opts: opts, redactor: DefaultRedactor(),
	}
	e.FactCheckPolicy = DefaultFactCheckPolicy()
	// Switching a new database to WAL takes an exclusive lock that SQLite
	// doesn't wait for, so processes creating a store at the same moment
	// can see SQLITE_BUSY. Retry briefly.
	for attempt := 0; ; attempt++ {
		err = e.setup()
		if err == nil || attempt == 20 || !strings.Contains(err.Error(), "SQLITE_BUSY") {
			break
		}
		time.Sleep(time.Duration(10+attempt*10) * time.Millisecond)
	}
	if err != nil {
		_ = db.Close() // already failing; report the first error
		return nil, err
	}
	if err := e.configureBeads(); err != nil {
		_ = db.Close() // already failing; report the first error
		return nil, err
	}
	return e, nil
}

// setup creates or migrates the schema and settles the replica id.
func (e *Engine) setup() error {
	if _, err := e.db.Exec(baseSchema); err != nil {
		return fmt.Errorf("schema: %w", err)
	}
	for _, m := range migrations {
		var n int
		if err := e.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?`, m.table, m.column).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			if _, err := e.db.Exec(m.ddl); err != nil {
				return fmt.Errorf("migrate %s.%s: %w", m.table, m.column, err)
			}
		}
	}
	if _, err := e.db.Exec(viewsSchema + rulesSchema); err != nil {
		return fmt.Errorf("schema: %w", err)
	}
	// Two processes opening a new store at once must agree on one id, so
	// insert-if-absent and read back rather than read-then-write.
	if _, err := e.db.Exec(`INSERT OR IGNORE INTO meta (key, value) VALUES ('replica_id', ?)`, newID("rep")); err != nil {
		return err
	}
	var err error
	if e.replica, err = e.meta("replica_id"); err != nil {
		return err
	}
	if err := e.checkFileIdentity(); err != nil {
		return err
	}
	if v, err := e.meta("views_version"); err != nil {
		return err
	} else if v != viewsVersion {
		if err := e.Rebuild(); err != nil {
			return err
		}
		return e.setMeta("views_version", viewsVersion)
	}
	return nil
}

// checkFileIdentity starts a new replica when the database file is a copy
// (restored from a backup, or cloned to another machine). A copy that kept
// writing under the old replica id would fork its chain for good: two files
// claiming the same feed with different events. The new replica continues
// from the copied events; the old chain stays as it was.
func (e *Engine) checkFileIdentity() error {
	id := fileIdentity(e.path)
	if id == "" {
		return nil
	}
	stored, err := e.meta("replica_file")
	if err != nil {
		return err
	}
	if stored != "" && stored != id {
		var n int
		if err := e.db.QueryRow(`SELECT COUNT(*) FROM events WHERE replica = ?`, e.replica).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			old := e.replica
			e.replica = newID("rep")
			if err := e.setMeta("replica_id", e.replica); err != nil {
				return err
			}
			if err := e.setMeta("replica_previous", old); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "smem: %s is a copy of replica %s; continuing as new replica %s\n", e.path, old, e.replica)
		}
	}
	if stored != id {
		return e.setMeta("replica_file", id)
	}
	return nil
}

// Clone opens a second handle on the same database with the same settings.
// Each handle has its own connection, so a slow operation on one (a
// fact-check waiting on a judge) doesn't hold up the other.
func (e *Engine) Clone() (*Engine, error) {
	c, err := OpenWith(e.path, e.opts)
	if err != nil {
		return nil, err
	}
	c.Now, c.Actor, c.Session, c.KeyDir = e.Now, e.Actor, e.Session, e.KeyDir
	c.PropagationDepth, c.Checkers, c.Judges, c.FactCheckPolicy = e.PropagationDepth, e.Checkers, e.Judges, e.FactCheckPolicy
	c.Policy, c.AllowNewKey, c.redactor, c.beadRe = e.Policy, e.AllowNewKey, e.redactor, e.beadRe
	return c, nil
}

// defaultActor is $SMEM_ACTOR, or who@host: client (e.g. claude-code) if
// given, else the user. Set an explicit actor (SMEM_ACTOR or "actor" in the
// local config) for agents whose hostname changes on restart.
func defaultActor(client string) string {
	if a := os.Getenv("SMEM_ACTOR"); a != "" {
		return a
	}
	who := client
	if who == "" {
		who = os.Getenv("USER")
	}
	if who == "" {
		who = "unknown"
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return who + "@" + strings.Split(h, ".")[0]
	}
	return who
}

// DefaultActorFor is the actor a client such as claude-code signs as when
// none is configured.
func DefaultActorFor(client string) string { return defaultActor(client) }

// Close closes the database.
func (e *Engine) Close() error { return e.db.Close() }

// Replica is this database's replica id.
func (e *Engine) Replica() string { return e.replica }

// Path is the database file path.
func (e *Engine) Path() string { return e.path }

func (e *Engine) meta(key string) (string, error) {
	var v string
	err := e.db.QueryRow(`SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

func (e *Engine) setMeta(key, value string) error {
	_, err := e.db.Exec(`INSERT INTO meta (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// wtx is a write transaction. Everything inside it must use w.tx: the pool
// has one connection, so touching e.db would deadlock.
type wtx struct {
	e       *Engine
	tx      *sql.Tx
	emitted []Event
}

func (e *Engine) write(fn func(*wtx) error) ([]Event, error) {
	tx, err := e.db.Begin()
	if err != nil {
		return nil, err
	}
	w := &wtx{e: e, tx: tx}
	if err := fn(w); err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return w.emitted, nil
}

// signer returns the actor's key, registering it in the log on first use.
func (w *wtx) signer() (ed25519.PrivateKey, string, error) {
	actor := w.e.Actor
	priv, ok := w.e.keys[actor]
	if !ok {
		var err error
		if priv, err = loadKey(w.e.KeyDir, actor); err != nil {
			return nil, "", err
		}
		if priv == nil {
			if err := w.checkNewIdentity(actor); err != nil {
				return nil, "", err
			}
			if priv, err = loadOrCreateKey(w.e.KeyDir, actor); err != nil {
				return nil, "", err
			}
		}
		w.e.keys[actor] = priv
	}
	pub := priv.Public().(ed25519.PublicKey)
	kid := keyID(pub)
	var n int
	if err := w.tx.QueryRow(`SELECT COUNT(*) FROM keys WHERE key_id = ?`, kid).Scan(&n); err != nil {
		return nil, "", err
	}
	if n == 0 {
		reg := keyRegistered{KeyID: kid, Actor: actor, PublicKey: base64.StdEncoding.EncodeToString(pub)}
		if _, err := w.emitWith(priv, kid, evKeyRegistered, kid, reg); err != nil {
			return nil, "", err
		}
		// Keys created on this machine are trusted here by default.
		if _, err := w.tx.Exec(`INSERT OR IGNORE INTO key_trust (key_id, trusted, note) VALUES (?, 1, 'local key')`, kid); err != nil {
			return nil, "", err
		}
	}
	return priv, kid, nil
}

// checkNewIdentity refuses to mint a second key for an actor that already
// signs events in this replica, unless AllowNewKey is set.
func (w *wtx) checkNewIdentity(actor string) error {
	if w.e.AllowNewKey {
		return nil
	}
	var kid string
	err := w.tx.QueryRow(`SELECT key_id FROM keys WHERE actor = ? AND replica = ? ORDER BY registered_at DESC LIMIT 1`,
		actor, w.e.replica).Scan(&kid)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	} else if err != nil {
		return err
	}
	return fmt.Errorf("actor %q already signs this store with %s, but its private key is not in %s. "+
		"The key directory was probably lost (is it on ephemeral storage?). Point SMEM_KEY_DIR or keys.dir "+
		"in the local config at persistent storage that holds %s.ed25519, or set keys.allow_new to start a new identity",
		actor, kid, w.e.KeyDir, unsafeName.ReplaceAllString(actor, "_"))
}

func (w *wtx) emit(typ, subject string, payload any) (Event, error) {
	priv, kid, err := w.signer()
	if err != nil {
		return Event{}, err
	}
	return w.emitWith(priv, kid, typ, subject, payload)
}

func (w *wtx) emitWith(priv ed25519.PrivateKey, kid, typ, subject string, payload any) (Event, error) {
	// Redact before hashing: the log is append-only, so a secret that gets
	// in can never be removed.
	raw, err := w.e.redactor.payload(payload)
	if err != nil {
		return Event{}, err
	}
	ev := Event{Replica: w.e.replica, Actor: w.e.Actor, KeyID: kid, Session: w.e.Session,
		Type: typ, Subject: subject, Payload: raw}
	err = w.tx.QueryRow(`SELECT rseq, hash FROM events WHERE replica = ? ORDER BY rseq DESC LIMIT 1`, w.e.replica).Scan(&ev.RSeq, &ev.Prev)
	if errors.Is(err, sql.ErrNoRows) {
		ev.Prev = genesisHash
	} else if err != nil {
		return Event{}, err
	}
	ev.RSeq++
	var maxAt sql.NullInt64
	if err := w.tx.QueryRow(`SELECT MAX(at) FROM events`).Scan(&maxAt); err != nil {
		return Event{}, err
	}
	ev.At = w.e.Now().UnixMilli()
	if maxAt.Valid && ev.At <= maxAt.Int64 {
		ev.At = maxAt.Int64 + 1
	}
	ev.seal(priv)
	if err := insertEvent(w.tx, &ev); err != nil {
		return Event{}, err
	}
	if err := apply(w.tx, ev); err != nil {
		return Event{}, fmt.Errorf("apply %s: %w", typ, err)
	}
	w.emitted = append(w.emitted, ev)
	return ev, nil
}

// lookup resolves a record id to its kind and status.
func (w *wtx) lookup(id string) (kind, status string, err error) {
	kind, _, _ = strings.Cut(id, "-")
	var q string
	switch kind {
	case "mem":
		q = `SELECT status FROM memories WHERE id = ?`
	case "dec":
		q = `SELECT status FROM decisions WHERE id = ?`
	case "asm":
		q = `SELECT status FROM assumptions WHERE id = ?`
	case "src":
		q = `SELECT '' FROM sources WHERE id = ?`
	case "act":
		q = `SELECT '' FROM actions WHERE id = ?`
	case "rule":
		q = `SELECT status FROM rules WHERE id = ?`
	case "fail":
		q = `SELECT '' FROM failures WHERE id = ?`
	default:
		return "", "", fmt.Errorf("%q is not a memory, decision, assumption, source, action, rule or failure id", id)
	}
	err = w.tx.QueryRow(q, id).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return kind, "", fmt.Errorf("no such record %s", id)
	}
	return kind, status, err
}

func (w *wtx) require(id, kind string, statuses ...string) error {
	k, st, err := w.lookup(id)
	if err != nil {
		return err
	}
	if k != kind {
		return fmt.Errorf("%s is not a %s", id, kindName[kind])
	}
	if len(statuses) == 0 {
		return nil
	}
	for _, s := range statuses {
		if st == s {
			return nil
		}
	}
	return fmt.Errorf("%s is %s (expected %s)", id, st, strings.Join(statuses, " or "))
}

var kindName = map[string]string{"mem": "memory", "dec": "decision", "asm": "assumption", "src": "source", "act": "action",
	"rule": "rule", "fail": "failure"}

func isRecordID(s string) bool {
	k, rest, ok := strings.Cut(s, "-")
	return ok && rest != "" && kindName[k] != ""
}

func newID(prefix string) string {
	b := make([]byte, 5)
	rand.Read(b)
	return prefix + "-" + hex.EncodeToString(b)
}

func ms(t time.Time) int64 { return t.UnixMilli() }

func fromMs(v int64) time.Time { return time.UnixMilli(v).UTC() }

func optTime(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := fromMs(v.Int64)
	return &t
}

func placeholders(n int) string {
	if n == 0 {
		return "NULL"
	}
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

func anys[T any](xs []T) []any {
	out := make([]any, len(xs))
	for i, x := range xs {
		out[i] = x
	}
	return out
}

// queryAll scans every row of a query with scan.
func queryAll[T any](rows *sql.Rows, err error, scan func(scanner) (T, error)) ([]T, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []T
	for rows.Next() {
		v, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

type querier interface {
	Query(string, ...any) (*sql.Rows, error)
}

func selectAll[T any](q querier, scan func(scanner) (T, error), query string, args ...any) ([]T, error) {
	rows, err := q.Query(query, args...)
	return queryAll(rows, err, scan)
}
