package smem

import (
	"database/sql"
	"encoding/json"
	"errors"
)

// Event payloads. These are the wire format: changing a field name changes
// what old events mean, so add fields rather than rename them.

type memoryAsserted struct {
	ID          string   `json:"id"`
	Kind        string   `json:"kind"`
	Content     string   `json:"content"`
	Scope       string   `json:"scope,omitempty"`
	Volatility  string   `json:"volatility"`
	Confidence  float64  `json:"confidence"`
	ValidFrom   int64    `json:"valid_from,omitempty"` // 0 = the event's recorded time
	DerivedFrom []string `json:"derived_from,omitempty"`
	Supersedes  string   `json:"supersedes,omitempty"`
}

type statusChange struct {
	ID         string  `json:"id"`
	Reason     string  `json:"reason,omitempty"`
	Cause      string  `json:"cause,omitempty"` // the record whose change triggered this one
	Root       string  `json:"root,omitempty"`  // where the propagation started
	ValidTo    int64   `json:"valid_to,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
	Salience   float64 `json:"salience,omitempty"`
}

type memorySignal struct {
	ID     string `json:"id"`
	Signal string `json:"signal"`
	Note   string `json:"note,omitempty"`
	// Boost is the share of remaining doubt a confirmation removes:
	// confidence c becomes 1 - (1-c)(1-boost).
	Boost float64 `json:"boost,omitempty"`
}

type recallHit struct {
	ID    string  `json:"id"`
	Score float64 `json:"score"`
}

type recallPayload struct {
	Query    string      `json:"query"`
	Results  []recallHit `json:"results"`
	Injected bool        `json:"injected,omitempty"` // shown at session start, not looked up
}

type sourceCaptured struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Ref         string `json:"ref"`
	ContentHash string `json:"content_hash,omitempty"`
	Note        string `json:"note,omitempty"`
}

type assumptionIn struct {
	ID        string `json:"id"`
	Statement string `json:"statement"`
	CheckHint string `json:"check_hint,omitempty"`
}

type decisionMade struct {
	ID          string         `json:"id"`
	Question    string         `json:"question"`
	Choice      string         `json:"choice"`
	Rationale   string         `json:"rationale,omitempty"`
	Rejected    []Option       `json:"rejected,omitempty"`
	Assumptions []assumptionIn `json:"assumptions,omitempty"`
	Used        []string       `json:"used,omitempty"`
	Evidence    []string       `json:"evidence,omitempty"`
	Bead        string         `json:"bead,omitempty"`
	Supersedes  string         `json:"supersedes,omitempty"`
	Snapshot    Snapshot       `json:"snapshot"`
}

type outcomePayload struct {
	ID      string `json:"id"`
	Outcome string `json:"outcome"`
	Note    string `json:"note,omitempty"`
}

type approvalPayload struct {
	ID       string `json:"id"`
	Approver string `json:"approver"`
	Scope    string `json:"scope,omitempty"`
	Note     string `json:"note,omitempty"`
	Seen     string `json:"seen"` // hash of the decision's latest event when approved
}

type actionPayload struct {
	ID         string `json:"id"`
	Decision   string `json:"decision,omitempty"`
	Bead       string `json:"bead,omitempty"`
	Tool       string `json:"tool,omitempty"`
	Summary    string `json:"summary,omitempty"`
	ArgsHash   string `json:"args_hash,omitempty"`
	ResultHash string `json:"result_hash,omitempty"`
	Commit     string `json:"commit,omitempty"`
	Transcript string `json:"transcript,omitempty"`
	Agent      string `json:"agent,omitempty"`       // subagent that made the call
	ObservedAt int64  `json:"observed_at,omitempty"` // when the hook saw it, if recorded later
	LinkedBy   string `json:"linked_by,omitempty"`   // how Decision was chosen: latest, unambiguous; empty = explicit
}

// signalWeight is how much each kind of access reinforces a memory.
var signalWeight = map[string]float64{
	"asserted": 1, "retrieved": 0.5, "used": 1, "cited": 1.5, "confirmed": 2, "reconfirmed": 1,
	"contradicted": 0,
}

// applier runs projection statements for one event, keeping the first error.
type applier struct {
	tx  *sql.Tx
	ev  Event
	at  int64 // the event's effective time
	err error
}

func (a *applier) exec(q string, args ...any) {
	if a.err == nil {
		_, a.err = a.tx.Exec(q, args...)
	}
}

func (a *applier) edge(src, dst, typ string) {
	a.exec(`INSERT INTO edges (src, dst, type, at, event) VALUES (?, ?, ?, ?, ?)`, src, dst, typ, a.at, a.ev.ID)
}

func (a *applier) access(id, signal string) {
	a.exec(`INSERT INTO accesses (memory_id, at, signal, weight, session, event) VALUES (?, ?, ?, ?, ?, ?)`,
		id, a.at, signal, signalWeight[signal], a.ev.Session, a.ev.ID)
}

func (a *applier) status(subject, status, cause, reason string) {
	a.exec(`INSERT INTO status_log (subject, at, status, cause, reason, actor, event) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		subject, a.at, status, cause, reason, a.ev.Actor, a.ev.ID)
}

// apply projects one event into the view tables. It must depend only on the
// event and on views built from earlier events, so that replaying the log in
// order always produces the same state.
//
// Events signed by a key that is not trusted locally are quarantined: they
// stay in the log (so chains still verify and nothing is lost) but are not
// projected, so they can't reach recall, context or review until someone
// runs `smem keys trust`. Key registrations are always projected, so the
// key can be listed and checked.
func apply(tx *sql.Tx, ev Event) error {
	if ev.Type != evKeyRegistered {
		ok, err := trusted(tx, ev.KeyID)
		if err != nil || !ok {
			return err
		}
	}
	a := &applier{tx: tx, ev: ev, at: ev.effAt()}
	decode := func(v any) bool {
		if a.err == nil {
			a.err = json.Unmarshal(ev.Payload, v)
		}
		return a.err == nil
	}
	switch ev.Type {
	case evKeyRegistered:
		var p keyRegistered
		if decode(&p) {
			a.exec(`INSERT OR IGNORE INTO keys (key_id, actor, public_key, replica, registered_at, event) VALUES (?, ?, ?, ?, ?, ?)`,
				p.KeyID, p.Actor, p.PublicKey, ev.Replica, a.at, ev.ID)
		}

	case evMemoryAsserted:
		var p memoryAsserted
		if !decode(&p) {
			break
		}
		validFrom := p.ValidFrom
		if validFrom == 0 {
			validFrom = a.at
		}
		a.exec(`INSERT INTO memories (id, kind, content, scope, volatility, confidence0, valid_from, recorded_at, status, supersedes, actor, session, event)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?)`,
			p.ID, p.Kind, p.Content, p.Scope, p.Volatility, p.Confidence, validFrom, a.at, p.Supersedes, ev.Actor, ev.Session, ev.ID)
		a.exec(`INSERT INTO memories_fts (id, content) VALUES (?, ?)`, p.ID, p.Content)
		a.access(p.ID, "asserted")
		for _, d := range p.DerivedFrom {
			a.edge(p.ID, d, "derived_from")
		}
		if p.Supersedes != "" {
			a.edge(p.ID, p.Supersedes, "supersedes")
			// First successor in log order wins; a second one is a fork that
			// Review reports as a conflict.
			a.exec(`UPDATE memories SET valid_to = ?, closed_at = ?, status = 'superseded', superseded_by = ?
				WHERE id = ? AND superseded_by = ''`, validFrom, a.at, p.ID, p.Supersedes)
			a.status(p.Supersedes, "superseded", p.ID, "")
		}

	case evMemoryInvalidated:
		var p statusChange
		if decode(&p) {
			validTo := p.ValidTo
			if validTo == 0 {
				validTo = a.at
			}
			a.exec(`UPDATE memories SET valid_to = ?, closed_at = ?, status = 'invalid' WHERE id = ?`, validTo, a.at, p.ID)
			a.status(p.ID, "invalid", p.Cause, p.Reason)
		}

	case evMemoryRetracted:
		var p statusChange
		if decode(&p) {
			a.exec(`UPDATE memories SET retracted_at = ?, status = 'retracted' WHERE id = ?`, a.at, p.ID)
			a.status(p.ID, "retracted", p.Cause, p.Reason)
		}

	case evMemorySuspected:
		var p statusChange
		if decode(&p) {
			a.exec(`UPDATE memories SET status = 'suspect' WHERE id = ? AND status = 'active'`, p.ID)
			a.status(p.ID, "suspected", p.Cause, p.Reason)
		}

	case evMemoryReconfirmed:
		var p statusChange
		if decode(&p) {
			a.exec(`UPDATE memories SET status = CASE WHEN status = 'suspect' THEN 'active' ELSE status END,
				confidence0 = CASE WHEN ? > 0 THEN ? ELSE confidence0 END WHERE id = ?`, p.Confidence, p.Confidence, p.ID)
			a.access(p.ID, "reconfirmed")
			a.status(p.ID, "reconfirmed", "", p.Reason)
		}

	case evMemorySignal:
		var p memorySignal
		if decode(&p) {
			a.access(p.ID, p.Signal)
			if p.Signal == "contradicted" {
				a.status(p.ID, "contradicted", "", p.Note)
			}
			if p.Signal == "confirmed" && p.Boost > 0 {
				a.exec(`UPDATE memories SET confidence0 = 1 - (1 - confidence0) * ? WHERE id = ?`, 1-min(p.Boost, 1), p.ID)
				a.status(p.ID, "confirmed", "", p.Note)
			}
		}

	case evMemoryArchived:
		var p statusChange
		if decode(&p) {
			a.exec(`UPDATE memories SET status = 'archived', archived_at = ? WHERE id = ?`, a.at, p.ID)
			a.status(p.ID, "archived", "", p.Reason)
		}

	case evRecall:
		var p recallPayload
		// Memories injected at session start were shown, not looked up:
		// counting that as use would let memories reinforce themselves.
		if decode(&p) && !p.Injected {
			for _, h := range p.Results {
				a.access(h.ID, "retrieved")
			}
		}

	case evSourceCaptured:
		var p sourceCaptured
		if decode(&p) {
			a.exec(`INSERT INTO sources (id, kind, ref, content_hash, note, captured_at) VALUES (?, ?, ?, ?, ?, ?)`,
				p.ID, p.Kind, p.Ref, p.ContentHash, p.Note, a.at)
		}

	case evDecisionMade:
		var p decisionMade
		if !decode(&p) {
			break
		}
		snap, _ := json.Marshal(p.Snapshot)
		a.exec(`INSERT INTO decisions (id, question, choice, rationale, status, decided_at, actor, session, bead, snapshot, supersedes, event)
			VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?)`,
			p.ID, p.Question, p.Choice, p.Rationale, a.at, ev.Actor, ev.Session, p.Bead, string(snap), p.Supersedes, ev.ID)
		a.exec(`INSERT INTO decisions_fts (id, question, choice, rationale) VALUES (?, ?, ?, ?)`, p.ID, p.Question, p.Choice, p.Rationale)
		a.exec(`INSERT INTO options (decision_id, option, chosen, reason) VALUES (?, ?, 1, ?)`, p.ID, p.Choice, p.Rationale)
		for _, o := range p.Rejected {
			a.exec(`INSERT INTO options (decision_id, option, chosen, reason) VALUES (?, ?, 0, ?)`, p.ID, o.Option, o.Reason)
		}
		for _, as := range p.Assumptions {
			a.exec(`INSERT INTO assumptions (id, decision_id, statement, check_hint, status) VALUES (?, ?, ?, ?, 'open')`,
				as.ID, p.ID, as.Statement, as.CheckHint)
		}
		for _, m := range p.Used {
			a.edge(p.ID, m, "used")
			a.access(m, "cited")
		}
		for _, s := range p.Evidence {
			a.edge(p.ID, s, "evidenced_by")
		}
		if p.Supersedes != "" {
			a.edge(p.ID, p.Supersedes, "supersedes")
			a.exec(`UPDATE decisions SET status = 'superseded', superseded_by = ? WHERE id = ? AND superseded_by = ''`, p.ID, p.Supersedes)
			a.status(p.Supersedes, "superseded", p.ID, "")
		}

	case evDecisionOutcome:
		var p outcomePayload
		if !decode(&p) {
			break
		}
		a.exec(`UPDATE decisions SET outcome = ?, outcome_note = ?, outcome_at = ? WHERE id = ?`, p.Outcome, p.Note, a.at, p.ID)
		a.status(p.ID, "outcome:"+p.Outcome, "", p.Note)
		// A decision that worked out reinforces what it relied on. A failure
		// does not weaken them automatically: the reasoning may be at fault.
		if p.Outcome == "success" {
			a.exec(`INSERT INTO accesses (memory_id, at, signal, weight, session, event)
				SELECT dst, ?, 'confirmed', ?, ?, ? FROM edges WHERE src = ? AND type = 'used'`,
				a.at, signalWeight["confirmed"], ev.Session, ev.ID, p.ID)
		}

	case evDecisionApproved:
		var p approvalPayload
		if decode(&p) {
			a.exec(`INSERT INTO approvals (decision_id, approver, scope, note, seen, at, actor, event) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
				p.ID, p.Approver, p.Scope, p.Note, p.Seen, a.at, ev.Actor, ev.ID)
			a.status(p.ID, "approved", "", p.Approver)
		}

	case evDecisionSuspected:
		var p statusChange
		if decode(&p) {
			a.exec(`UPDATE decisions SET status = 'suspect' WHERE id = ? AND status = 'active'`, p.ID)
			a.status(p.ID, "suspected", p.Cause, p.Reason)
		}

	case evDecisionReaffirmed:
		var p statusChange
		if decode(&p) {
			a.exec(`UPDATE decisions SET status = 'active' WHERE id = ? AND status = 'suspect'`, p.ID)
			a.status(p.ID, "reaffirmed", "", p.Reason)
		}

	case evDecisionReverted:
		var p statusChange
		if decode(&p) {
			a.exec(`UPDATE decisions SET status = 'reverted' WHERE id = ?`, p.ID)
			a.status(p.ID, "reverted", "", p.Reason)
		}

	case evAssumptionBroken, evAssumptionHeld:
		var p statusChange
		if decode(&p) {
			st := "held"
			if ev.Type == evAssumptionBroken {
				st = "broken"
			}
			a.exec(`UPDATE assumptions SET status = ?, checked_at = ?, note = ? WHERE id = ?`, st, a.at, p.Reason, p.ID)
			a.status(p.ID, st, "", p.Reason)
		}

	case evJudgmentRecorded:
		var p judgmentRecorded
		if decode(&p) {
			a.exec(`INSERT INTO judgments (id, subject, at, verdict, confidence, decided_by, action, reason, actor, input_hash, judge_calls, replica, event)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				p.ID, p.Subject, a.at, p.Verdict.Label, p.Verdict.Confidence, p.DecidedBy, p.Action, p.Verdict.Reason, ev.Actor,
				p.InputHash, len(p.Judges), ev.Replica, ev.ID)
			for _, j := range p.Judges {
				a.exec(`INSERT INTO judge_runs (judgment, judge, ok, status, error, at, replica) VALUES (?, ?, 1, 200, '', ?, ?)`,
					p.ID, j.Judge, a.at, ev.Replica)
			}
			for _, je := range p.JudgeErrors {
				a.exec(`INSERT INTO judge_runs (judgment, judge, ok, status, error, at, replica) VALUES (?, ?, 0, ?, ?, ?, ?)`,
					p.ID, je.Judge, je.Status, je.Error, a.at, ev.Replica)
			}
		}

	case evActionRecorded:
		var p actionPayload
		if decode(&p) {
			a.exec(`INSERT INTO actions (id, at, actor, session, decision_id, bead, tool, summary, args_hash, result_hash, commit_sha, transcript, event)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				p.ID, a.at, ev.Actor, ev.Session, p.Decision, p.Bead, p.Tool, p.Summary, p.ArgsHash, p.ResultHash, p.Commit, p.Transcript, ev.ID)
		}

	default:
		applyRuleEvent(a, ev, decode)
	}
	// Unknown event types are kept in the log and skipped here, so an older
	// binary can still replay a log written by a newer one.
	return a.err
}

// trusted reports whether events signed by keyID are projected.
func trusted(q interface {
	QueryRow(string, ...any) *sql.Row
}, keyID string) (bool, error) {
	var t bool
	err := q.QueryRow(`SELECT trusted FROM key_trust WHERE key_id = ?`, keyID).Scan(&t)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return t, err
}

// orderSensitive reports whether applying ev after events that follow it in
// log order could give a different result than replaying in order. Inserts
// and access records commute; status changes and "first successor wins"
// supersedes do not.
func orderSensitive(ev Event) bool {
	switch ev.Type {
	case evMemorySignal:
		// A confirmation changes confidence0, and reconfirm can set it
		// outright: the two don't commute.
		var p memorySignal
		_ = json.Unmarshal(ev.Payload, &p) // unreadable: no boost, so it commutes
		return p.Boost > 0
	case evKeyRegistered, evRecall, evSourceCaptured, evActionRecorded,
		evJudgmentRecorded, evDecisionApproved, evFailureRecorded, evRuleProposed, evRuleViolated:
		return false
	case evMemoryAsserted, evDecisionMade:
		var p struct {
			Supersedes string `json:"supersedes"`
		}
		_ = json.Unmarshal(ev.Payload, &p) // unreadable: treated as a plain insert
		return p.Supersedes != ""
	}
	return true
}
