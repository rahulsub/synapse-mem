package smem

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Source is an external artifact something was based on.
type Source struct {
	ID          string    `json:"id"`
	Kind        string    `json:"kind"`
	Ref         string    `json:"ref"`
	ContentHash string    `json:"content_hash,omitempty"`
	Note        string    `json:"note,omitempty"`
	CapturedAt  time.Time `json:"captured_at"`
}

// Approval is a sign-off on a decision.
type Approval struct {
	Approver string    `json:"approver"`
	Scope    string    `json:"scope,omitempty"`
	Note     string    `json:"note,omitempty"`
	Seen     string    `json:"seen"`
	At       time.Time `json:"at"`
	Actor    string    `json:"actor"`
}

// Action is recorded work.
type Action struct {
	ID         string    `json:"id"`
	At         time.Time `json:"at"`
	Actor      string    `json:"actor"`
	Session    string    `json:"session,omitempty"`
	DecisionID string    `json:"decision_id,omitempty"`
	Bead       string    `json:"bead,omitempty"`
	Tool       string    `json:"tool,omitempty"`
	Summary    string    `json:"summary,omitempty"`
	Commit     string    `json:"commit,omitempty"`
	Transcript string    `json:"transcript,omitempty"`
}

// StatusEntry is one change in a record's status, with its cause.
type StatusEntry struct {
	At     time.Time `json:"at"`
	Status string    `json:"status"`
	Cause  string    `json:"cause,omitempty"`
	Reason string    `json:"reason,omitempty"`
	Actor  string    `json:"actor"`
	Event  string    `json:"event"`
}

// Link is an edge to another record, with a one-line label.
type Link struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Label string `json:"label"`
}

// DecisionTrace is everything recorded about why a decision was made and
// what came of it.
type DecisionTrace struct {
	Decision    Decision      `json:"decision"`
	Rejected    []Option      `json:"rejected"`
	Assumptions []Assumption  `json:"assumptions"`
	Used        []Memory      `json:"used"`    // the versions relied on, with their current status
	Context     []Memory      `json:"context"` // what else was in view
	Snapshot    Snapshot      `json:"snapshot"`
	Evidence    []Source      `json:"evidence"`
	Approvals   []Approval    `json:"approvals"`
	Actions     []Action      `json:"actions"`
	History     []StatusEntry `json:"history"`
	Signers     []string      `json:"signers"` // actor/key of each event about this decision
}

// MemoryTrace is the provenance of one memory.
type MemoryTrace struct {
	Memory      Memory         `json:"memory"`
	Lineage     []Memory       `json:"lineage"` // oldest version first
	DerivedFrom []Link         `json:"derived_from"`
	UsedBy      []Link         `json:"used_by"`
	Dependents  []Link         `json:"dependents"`
	Signals     map[string]int `json:"signals"`
	Judgments   []Judgment     `json:"judgments"`
	History     []StatusEntry  `json:"history"`
}

// Trace answers "why?" for any reference.
type Trace struct {
	Ref        string          `json:"ref"`
	Kind       string          `json:"kind"`
	Decisions  []DecisionTrace `json:"decisions,omitempty"`
	Memory     *MemoryTrace    `json:"memory,omitempty"`
	Assumption *Assumption     `json:"assumption,omitempty"`
	Source     *Source         `json:"source,omitempty"`
	Actions    []Action        `json:"actions,omitempty"`
	Derived    []Link          `json:"derived,omitempty"`
	Rule       *RuleTrace      `json:"rule,omitempty"`
	Failure    *Failure        `json:"failure,omitempty"`
	Notes      []string        `json:"notes,omitempty"`
}

// RuleTrace is why a rule exists and how it has fared.
type RuleTrace struct {
	Rule     Rule          `json:"rule"`
	Failures []Failure     `json:"failures"` // with its label, before admission
	Since    []Failure     `json:"since"`    // with its label, after admission: it didn't prevent these
	Replaces []Link        `json:"replaces"`
	Rules    []Link        `json:"rules"` // rules this failure helped justify (failure traces)
	History  []StatusEntry `json:"history"`
}

var decisionTrailer = regexp.MustCompile(`(?im)^Decision:\s*(dec-[0-9a-f]+)\s*$`)

// Why traces a reference: a decision, memory, assumption, source or action
// id; a git commit (via recorded actions and "Decision:" commit trailers);
// or a bead id.
func (e *Engine) Why(ref string) (*Trace, error) {
	ref = strings.TrimSpace(ref)
	t := &Trace{Ref: ref}
	kind, _, _ := strings.Cut(ref, "-")
	var err error
	switch {
	case kind == "dec" && isRecordID(ref):
		t.Kind = "decision"
		err = e.addDecisions(t, ref)
	case kind == "mem" && isRecordID(ref):
		t.Kind = "memory"
		t.Memory, err = e.memoryTrace(ref)
	case kind == "asm" && isRecordID(ref):
		t.Kind = "assumption"
		var a Assumption
		if a, err = scanAssumption(e.db.QueryRow(`SELECT `+assumptionCols+` FROM assumptions WHERE id = ?`, ref)); err == nil {
			t.Assumption = &a
			err = e.addDecisions(t, a.DecisionID)
		}
	case kind == "src" && isRecordID(ref):
		t.Kind = "source"
		var s Source
		if s, err = scanSource(e.db.QueryRow(`SELECT `+sourceCols+` FROM sources WHERE id = ?`, ref)); err == nil {
			t.Source = &s
			t.Derived, err = e.links(`SELECT e.src, e.type FROM edges e WHERE e.dst = ? ORDER BY e.at`, ref)
		}
	case kind == "act" && isRecordID(ref):
		t.Kind = "action"
		if t.Actions, err = e.actions(`id = ?`, ref); err == nil && len(t.Actions) > 0 && t.Actions[0].DecisionID != "" {
			err = e.addDecisions(t, t.Actions[0].DecisionID)
		}
	case kind == "rule" && isRecordID(ref):
		t.Kind = "rule"
		if t.Rule, err = e.ruleTrace(ref); err == nil && t.Rule.Rule.Why.Decision != "" {
			err = e.addDecisions(t, t.Rule.Rule.Why.Decision)
		}
	case kind == "fail" && isRecordID(ref):
		t.Kind = "failure"
		var fs []Failure
		if fs, err = e.failures(`id = ?`, ref); err == nil && len(fs) == 1 {
			t.Failure = &fs[0]
			t.Derived, err = e.links(`SELECT id, 'rule' FROM rules WHERE label = ? AND label != '' ORDER BY proposed_at`, fs[0].Label)
		}
	case hexRef.MatchString(ref):
		t.Kind = "commit"
		err = e.commitTrace(t, ref)
	default:
		t.Kind = "bead"
		if t.Actions, err = e.actions(`bead = ?`, ref); err == nil {
			var ids []string
			// Decisions for the bead, or citing it as evidence.
			if ids, err = e.strings(`SELECT id FROM decisions WHERE bead = ? OR id IN
				(SELECT e.src FROM edges e JOIN sources s ON s.id = e.dst WHERE e.type = 'evidenced_by' AND s.ref = ?)
				ORDER BY decided_at`, ref, ref); err == nil {
				err = e.addDecisions(t, ids...)
			}
		}
	}
	if err != nil {
		return nil, err
	}
	if t.Memory == nil && t.Source == nil && t.Assumption == nil && t.Rule == nil && t.Failure == nil &&
		len(t.Decisions) == 0 && len(t.Actions) == 0 {
		return nil, fmt.Errorf("nothing recorded for %s", ref)
	}
	return t, nil
}

func (e *Engine) commitTrace(t *Trace, sha string) error {
	acts, err := e.actions(`commit_sha != '' AND (commit_sha LIKE ? || '%' OR ? LIKE commit_sha || '%')`, sha, sha)
	if err != nil {
		return err
	}
	t.Actions = acts
	var ids []string
	for _, a := range acts {
		if a.DecisionID != "" {
			ids = append(ids, a.DecisionID)
		}
	}
	if out, err := exec.Command("git", "show", "-s", "--format=%B", sha, "--").Output(); err == nil { //nolint:gosec,noctx // sha matched hexRef
		for _, m := range decisionTrailer.FindAllStringSubmatch(string(out), -1) {
			ids = append(ids, m[1])
		}
	} else {
		t.Notes = append(t.Notes, "git lookup failed; only recorded actions were searched")
	}
	return e.addDecisions(t, dedupe(ids)...)
}

func (e *Engine) addDecisions(t *Trace, ids ...string) error {
	for _, id := range ids {
		dt, err := e.decisionTrace(id)
		if err != nil {
			return err
		}
		t.Decisions = append(t.Decisions, *dt)
	}
	return nil
}

func (e *Engine) decisionTrace(id string) (*DecisionTrace, error) {
	d, err := e.Decision(id)
	if err != nil {
		return nil, err
	}
	dt := &DecisionTrace{Decision: d}
	_ = json.Unmarshal(d.Snapshot, &dt.Snapshot) // projected from a verified event; empty if absent
	if dt.Rejected, err = selectAll(e.db, func(s scanner) (Option, error) {
		var o Option
		return o, s.Scan(&o.Option, &o.Reason)
	}, `SELECT option, reason FROM options WHERE decision_id = ? AND chosen = 0 ORDER BY rowid`, id); err != nil {
		return nil, err
	}
	if dt.Assumptions, err = selectAll(e.db, scanAssumption, `SELECT `+assumptionCols+` FROM assumptions WHERE decision_id = ? ORDER BY rowid`, id); err != nil {
		return nil, err
	}
	if dt.Used, err = selectAll(e.db, scanMemory, `SELECT `+prefixed("m", memoryCols)+` FROM edges e JOIN memories m ON m.id = e.dst
		WHERE e.src = ? AND e.type = 'used' ORDER BY e.rowid`, id); err != nil {
		return nil, err
	}
	if ctx := dt.Snapshot.Memories; len(ctx) > 0 {
		if dt.Context, err = selectAll(e.db, scanMemory, `SELECT `+memoryCols+` FROM memories WHERE id IN (`+placeholders(len(ctx))+`)`, anys(ctx)...); err != nil {
			return nil, err
		}
	}
	if dt.Evidence, err = selectAll(e.db, scanSource, `SELECT `+prefixed("s", sourceCols)+` FROM edges e JOIN sources s ON s.id = e.dst
		WHERE e.src = ? AND e.type = 'evidenced_by' ORDER BY e.rowid`, id); err != nil {
		return nil, err
	}
	if dt.Approvals, err = selectAll(e.db, func(s scanner) (Approval, error) {
		var a Approval
		var at int64
		err := s.Scan(&a.Approver, &a.Scope, &a.Note, &a.Seen, &at, &a.Actor)
		a.At = fromMs(at)
		return a, err
	}, `SELECT approver, scope, note, seen, at, actor FROM approvals WHERE decision_id = ? ORDER BY at`, id); err != nil {
		return nil, err
	}
	if dt.Actions, err = e.actions(`decision_id = ?`, id); err != nil {
		return nil, err
	}
	if dt.History, err = e.history(id); err != nil {
		return nil, err
	}
	dt.Signers, err = e.strings(`SELECT DISTINCT actor || ' (' || key_id || ')' FROM events WHERE subject = ? ORDER BY 1`, id)
	return dt, err
}

func (e *Engine) memoryTrace(id string) (*MemoryTrace, error) {
	m, err := e.Memory(id)
	if err != nil {
		return nil, err
	}
	mt := &MemoryTrace{Memory: m, Signals: map[string]int{}}
	// Walk back to the first version, then forward to the newest.
	first := m
	for first.Supersedes != "" {
		prev, err := e.Memory(first.Supersedes)
		if err != nil {
			break
		}
		first = prev
	}
	for cur, seen := first, map[string]bool{}; !seen[cur.ID]; {
		seen[cur.ID] = true
		mt.Lineage = append(mt.Lineage, cur)
		if cur.SupersededBy == "" {
			break
		}
		next, err := e.Memory(cur.SupersededBy)
		if err != nil {
			break
		}
		cur = next
	}
	if mt.DerivedFrom, err = e.links(`SELECT dst, type FROM edges WHERE src = ? AND type = 'derived_from' ORDER BY at`, id); err != nil {
		return nil, err
	}
	if mt.UsedBy, err = e.links(`SELECT src, type FROM edges WHERE dst = ? AND type = 'used' ORDER BY at`, id); err != nil {
		return nil, err
	}
	if mt.Dependents, err = e.links(`SELECT src, type FROM edges WHERE dst = ? AND type = 'derived_from' ORDER BY at`, id); err != nil {
		return nil, err
	}
	type count struct {
		signal string
		n      int
	}
	counts, err := selectAll(e.db, func(s scanner) (count, error) {
		var c count
		return c, s.Scan(&c.signal, &c.n)
	}, `SELECT signal, COUNT(*) FROM accesses WHERE memory_id = ? GROUP BY signal`, id)
	if err != nil {
		return nil, err
	}
	for _, c := range counts {
		mt.Signals[c.signal] = c.n
	}
	if mt.Judgments, err = e.judgments(id); err != nil {
		return nil, err
	}
	mt.History, err = e.history(id)
	return mt, err
}

func (e *Engine) history(id string) ([]StatusEntry, error) {
	return selectAll(e.db, func(s scanner) (StatusEntry, error) {
		var h StatusEntry
		var at int64
		err := s.Scan(&at, &h.Status, &h.Cause, &h.Reason, &h.Actor, &h.Event)
		h.At = fromMs(at)
		return h, err
	}, `SELECT at, status, cause, reason, actor, event FROM status_log WHERE subject = ? ORDER BY at`, id)
}

func (e *Engine) actions(where string, args ...any) ([]Action, error) {
	return selectAll(e.db, func(s scanner) (Action, error) {
		var a Action
		var at int64
		err := s.Scan(&a.ID, &at, &a.Actor, &a.Session, &a.DecisionID, &a.Bead, &a.Tool, &a.Summary, &a.Commit, &a.Transcript)
		a.At = fromMs(at)
		return a, err
	}, `SELECT id, at, actor, session, decision_id, bead, tool, summary, commit_sha, transcript FROM actions WHERE `+where+` ORDER BY at`, args...)
}

// links resolves (id, type) rows into labelled links.
func (e *Engine) links(q string, args ...any) ([]Link, error) {
	ls, err := selectAll(e.db, func(s scanner) (Link, error) {
		var l Link
		return l, s.Scan(&l.ID, &l.Type)
	}, q, args...)
	if err != nil {
		return nil, err
	}
	for i := range ls {
		ls[i].Label = e.label(ls[i].ID)
	}
	return ls, nil
}

func (e *Engine) label(id string) string {
	var s string
	switch kind, _, _ := strings.Cut(id, "-"); kind {
	case "mem":
		_ = e.db.QueryRow(`SELECT '[' || status || '] ' || content FROM memories WHERE id = ?`, id).Scan(&s) // a missing record gets no label
	case "dec":
		_ = e.db.QueryRow(`SELECT '[' || status || '] ' || question || ' → ' || choice FROM decisions WHERE id = ?`, id).Scan(&s) // a missing record gets no label
	case "src":
		_ = e.db.QueryRow(`SELECT kind || ': ' || ref FROM sources WHERE id = ?`, id).Scan(&s) // a missing record gets no label
	case "rule":
		_ = e.db.QueryRow(`SELECT '[' || status || '] ' || text FROM rules WHERE id = ?`, id).Scan(&s) // a missing record gets no label
	case "fail":
		_ = e.db.QueryRow(`SELECT '[' || label || '] ' || summary FROM failures WHERE id = ?`, id).Scan(&s) // a missing record gets no label
	}
	return oneLine(s, 120)
}

func (e *Engine) strings(q string, args ...any) ([]string, error) {
	return selectAll(e.db, func(s scanner) (string, error) {
		var v string
		return v, s.Scan(&v)
	}, q, args...)
}

const sourceCols = `id, kind, ref, content_hash, note, captured_at`

func scanSource(s scanner) (Source, error) {
	var src Source
	var at int64
	err := s.Scan(&src.ID, &src.Kind, &src.Ref, &src.ContentHash, &src.Note, &at)
	src.CapturedAt = fromMs(at)
	return src, err
}

func prefixed(alias, cols string) string {
	parts := strings.Split(cols, ",")
	for i, p := range parts {
		parts[i] = alias + "." + strings.TrimSpace(p)
	}
	return strings.Join(parts, ", ")
}

// Text renders a trace for people.
func (t *Trace) Text() string {
	var b strings.Builder
	p := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	when := func(x time.Time) string { return x.Local().Format("2006-01-02 15:04") }
	if r := t.Rule; r != nil {
		p("rule %s [%s]%s\n  %s\n", r.Rule.ID, r.Rule.Status, map[bool]string{true: " scope " + r.Rule.Scope}[r.Rule.Scope != ""], r.Rule.Text)
		w := r.Rule.Why
		p("  proposed %s by %s", when(r.Rule.ProposedAt), r.Rule.Actor)
		if r.Rule.Source != "" {
			p(" from %s", r.Rule.Source)
		}
		p("\n  reason given: %s", cmp(w.Kind, "none"))
		if w.By != "" {
			p(" by %s", w.By)
		}
		if w.Quote != "" {
			p(": %q", w.Quote)
		}
		if w.Transcript != "" {
			p(" (%s)", w.Transcript)
		}
		if w.EnforcedBy != "" {
			p("; enforced by %s", w.EnforcedBy)
		}
		p("\n")
		if r.Rule.Basis != "" {
			p("  admitted: %s\n", r.Rule.Basis)
		}
		if r.Rule.Held != "" {
			p("  held: %s\n", r.Rule.Held)
		}
		for _, f := range r.Failures {
			p("  failure %s %s [%s] %s\n", f.ID, when(f.At), f.Label, oneLine(f.Summary, 100))
		}
		if len(r.Since) > 0 {
			p("  %d %q failure(s) since it was admitted:\n", len(r.Since), r.Rule.Label)
			for _, f := range r.Since {
				p("    %s %s %s\n", f.ID, when(f.At), oneLine(f.Summary, 100))
			}
		}
		if r.Rule.Violations > 0 {
			p("  violated %d time(s)\n", r.Rule.Violations)
		}
		for _, l := range r.Replaces {
			p("  replaces %s: %s\n", l.ID, l.Label)
		}
		writeHistory(&b, r.History)
	}
	if f := t.Failure; f != nil {
		p("failure %s [%s] %s by %s\n  %s\n", f.ID, f.Label, when(f.At), f.Actor, f.Summary)
		if f.Ref != "" {
			p("  ref: %s\n", f.Ref)
		}
		for _, l := range t.Derived {
			p("  label shared by rule %s: %s\n", l.ID, l.Label)
		}
	}
	for _, n := range t.Notes {
		p("note: %s\n", n)
	}
	if t.Assumption != nil {
		a := t.Assumption
		p("Assumption %s [%s]: %s\n", a.ID, a.Status, a.Statement)
		if a.CheckHint != "" {
			p("  check: %s\n", a.CheckHint)
		}
		if a.Note != "" {
			p("  note:  %s\n", a.Note)
		}
		p("\n")
	}
	if t.Source != nil {
		s := t.Source
		p("Source %s (%s): %s\n  captured %s %s\n", s.ID, s.Kind, s.Ref, when(s.CapturedAt), s.ContentHash)
		for _, l := range t.Derived {
			p("  ← %s %s  %s\n", l.Type, l.ID, l.Label)
		}
		p("\n")
	}
	if m := t.Memory; m != nil {
		mm := m.Memory
		p("Memory %s [%s] (%s, %s)\n  %s\n", mm.ID, mm.Status, mm.Kind, mm.Volatility, mm.Content)
		p("  valid from %s", when(mm.ValidFrom))
		if mm.ValidTo != nil {
			p(" to %s", when(*mm.ValidTo))
		}
		p("; recorded %s by %s\n", when(mm.RecordedAt), mm.Actor)
		if len(m.Lineage) > 1 {
			p("  versions:\n")
			for _, v := range m.Lineage {
				mark := " "
				if v.ID == mm.ID {
					mark = "*"
				}
				p("   %s %s [%s] %s\n", mark, v.ID, v.Status, oneLine(v.Content, 100))
			}
		}
		for _, l := range m.DerivedFrom {
			p("  derived from %s  %s\n", l.ID, l.Label)
		}
		for _, l := range m.UsedBy {
			p("  used by %s  %s\n", l.ID, l.Label)
		}
		for _, l := range m.Dependents {
			p("  basis for %s  %s\n", l.ID, l.Label)
		}
		if len(m.Signals) > 0 {
			p("  signals: %v\n", m.Signals)
		}
		for _, j := range m.Judgments {
			p("  fact-check %s %s: %s %.2f by %s → %s", j.ID, when(j.At), j.Verdict, j.Confidence, j.DecidedBy, j.Action)
			if j.Reason != "" {
				p(" (%s)", oneLine(j.Reason, 100))
			}
			p("\n")
		}
		writeHistory(&b, m.History)
		p("\n")
	}
	for _, dt := range t.Decisions {
		d := dt.Decision
		p("Decision %s [%s]  %s by %s\n", d.ID, d.Status, when(d.DecidedAt), d.Actor)
		p("  Q: %s\n  → %s\n", d.Question, d.Choice)
		if d.Rationale != "" {
			p("  why: %s\n", d.Rationale)
		}
		for _, o := range dt.Rejected {
			p("  rejected: %s", o.Option)
			if o.Reason != "" {
				p(" (%s)", o.Reason)
			}
			p("\n")
		}
		for _, a := range dt.Assumptions {
			p("  assumes %s [%s]: %s", a.ID, a.Status, a.Statement)
			if a.CheckHint != "" {
				p("  (check: %s)", a.CheckHint)
			}
			p("\n")
		}
		for _, m := range dt.Used {
			p("  relied on %s [%s] %s\n", m.ID, m.Status, oneLine(m.Content, 100))
			if m.SupersededBy != "" {
				p("     now superseded by %s\n", m.SupersededBy)
			}
		}
		if n := len(dt.Context); n > 0 {
			p("  had %d memories in view", n)
			if dt.Snapshot.Recall != "" {
				p(" (from recall %s)", dt.Snapshot.Recall)
			}
			p("\n")
		}
		if s := dt.Snapshot; s.Model != "" || s.PromptHash != "" {
			p("  model %s", s.Model)
			if s.PromptHash != "" {
				p(", prompt %s", s.PromptHash)
			}
			p("\n")
		}
		for _, s := range dt.Evidence {
			p("  evidence %s (%s): %s\n", s.ID, s.Kind, s.Ref)
		}
		if d.Bead != "" {
			p("  bead: %s\n", d.Bead)
		}
		for _, a := range dt.Approvals {
			p("  approved by %s %s (saw %s)\n", a.Approver, when(a.At), a.Seen[:12])
		}
		for _, a := range dt.Actions {
			p("  did %s %s %s", when(a.At), a.Tool, oneLine(a.Summary, 80))
			if a.Commit != "" {
				p(" [%s]", a.Commit)
			}
			p("\n")
		}
		if d.Outcome != "" {
			p("  outcome: %s %s\n", d.Outcome, d.OutcomeNote)
		}
		if d.SupersededBy != "" {
			p("  superseded by %s\n", d.SupersededBy)
		}
		writeHistory(&b, dt.History)
		p("  signed by: %s\n\n", strings.Join(dt.Signers, ", "))
	}
	if len(t.Decisions) == 0 {
		for _, a := range t.Actions {
			p("Action %s %s %s %s %s\n", a.ID, when(a.At), a.Actor, a.Tool, oneLine(a.Summary, 80))
		}
	}
	return b.String()
}

func writeHistory(b *strings.Builder, h []StatusEntry) {
	for _, s := range h {
		fmt.Fprintf(b, "  %s %s", s.At.Local().Format("2006-01-02 15:04"), s.Status)
		if s.Cause != "" {
			fmt.Fprintf(b, " because %s", s.Cause)
		}
		if s.Reason != "" {
			fmt.Fprintf(b, ": %s", s.Reason)
		}
		fmt.Fprintf(b, " (%s)\n", s.Actor)
	}
}

func (e *Engine) failures(where string, args ...any) ([]Failure, error) {
	return selectAll(e.db, func(s scanner) (Failure, error) {
		var f Failure
		var at int64
		err := s.Scan(&f.ID, &f.Label, &f.Summary, &f.Ref, &at, &f.Actor, &f.Session)
		f.At = fromMs(at)
		return f, err
	}, `SELECT id, label, summary, ref, at, actor, session FROM failures WHERE `+where+` ORDER BY at`, args...)
}

func (e *Engine) ruleTrace(id string) (*RuleTrace, error) {
	r, err := e.Rule(id)
	if err != nil {
		return nil, err
	}
	rt := &RuleTrace{Rule: r}
	cut := ms(r.ProposedAt)
	if r.AdmittedAt != nil {
		cut = ms(*r.AdmittedAt)
	}
	if r.Label != "" {
		if rt.Failures, err = e.failures(`label = ? AND at <= ?`, r.Label, cut); err != nil {
			return nil, err
		}
		if r.AdmittedAt != nil {
			if rt.Since, err = e.failures(`label = ? AND at > ?`, r.Label, cut); err != nil {
				return nil, err
			}
		}
	}
	for _, f := range r.Why.Failures {
		if fs, err := e.failures(`id = ?`, f); err == nil && len(fs) == 1 && !slices.ContainsFunc(rt.Failures, func(x Failure) bool { return x.ID == f }) {
			rt.Failures = append(rt.Failures, fs[0])
		}
	}
	if rt.Replaces, err = e.links(`SELECT dst, type FROM edges WHERE src = ? AND type = 'supersedes' ORDER BY at`, id); err != nil {
		return nil, err
	}
	rt.History, err = e.history(id)
	return rt, err
}
