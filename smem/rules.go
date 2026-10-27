package smem

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/rahulsub/synapse-mem/judge"
)

// Rules are standing instructions for agents: "run make test before
// committing", "never edit generated files". Left alone, agents pile them up
// with no record of why, until nobody can tell which still matter. Here a
// rule is a record like any other, and it is only admitted (made active,
// and so rendered into CLAUDE.md or injected) with a reason:
//
//   - requested: a person asked for it. Who, and their words.
//   - incident: the same kind of failure happened repeatedly (failures are
//     recorded with a label). Ideally a test or check now enforces it.
//   - decision: it carries out a recorded, still-active decision.
//
// Anything else stays a proposal: kept, visible to rationalize, but not
// used. Proposals are promoted when enough failures accumulate or a person
// approves them. A near-duplicate of an active rule, or a rule beyond the
// per-scope cap, is held too. A rule resting on a decision is flagged when
// the decision is, like any other dependent.

const (
	evFailureRecorded = "failure.recorded"
	evRuleProposed    = "rule.proposed"
	evRuleAdmitted    = "rule.admitted"
	evRuleRejected    = "rule.rejected"
	evRuleRetired     = "rule.retired"
	evRuleSuspected   = "rule.suspected"
	evRuleReaffirmed  = "rule.reaffirmed"
	evRuleViolated    = "rule.violated"
)

// Justification is the reason given for a rule.
type Justification struct {
	// Kind is requested, incident, decision, approved, merge or imported.
	Kind       string   `json:"kind,omitempty"`
	By         string   `json:"by,omitempty"`         // who asked or approved
	Quote      string   `json:"quote,omitempty"`      // their words
	Transcript string   `json:"transcript,omitempty"` // where they said it
	Failures   []string `json:"failures,omitempty"`   // fail- ids
	Decision   string   `json:"decision,omitempty"`   // dec- id
	EnforcedBy string   `json:"enforced_by,omitempty"`
}

// RuleInput proposes a rule.
type RuleInput struct {
	Text  string
	Scope string
	// Label ties the rule to a failure label: failures with it count toward
	// admission, and failures after admission show the rule isn't working.
	Label      string
	Why        Justification
	Supersedes []string
	Source     string // where an imported rule came from, file:line
}

// Rule is a rule and its state.
type Rule struct {
	ID           string        `json:"id"`
	Text         string        `json:"text"`
	Scope        string        `json:"scope,omitempty"`
	Label        string        `json:"label,omitempty"`
	Status       string        `json:"status"` // proposed, active, suspect, retired, rejected
	Why          Justification `json:"why"`
	Basis        string        `json:"basis,omitempty"` // why it was admitted
	Held         string        `json:"held,omitempty"`  // why it wasn't
	Source       string        `json:"source,omitempty"`
	ProposedAt   time.Time     `json:"proposed_at"`
	AdmittedAt   *time.Time    `json:"admitted_at,omitempty"`
	RetiredAt    *time.Time    `json:"retired_at,omitempty"`
	SupersededBy string        `json:"superseded_by,omitempty"`
	Violations   int           `json:"violations"`
	LastActivity time.Time     `json:"last_activity"`
	Actor        string        `json:"actor"`
}

// Failure is a recorded failure.
type Failure struct {
	ID      string    `json:"id"`
	Label   string    `json:"label"`
	Summary string    `json:"summary"`
	Ref     string    `json:"ref,omitempty"`
	At      time.Time `json:"at"`
	Actor   string    `json:"actor"`
	Session string    `json:"session,omitempty"`
}

// FailureInput records a failure: a broken build, a reverted change, a
// mistake someone had to correct. Label groups failures of the same kind.
type FailureInput struct {
	Label   string
	Summary string
	Ref     string // test path, commit, bead, URL
}

// RuleOutcome is what happened to a proposed or approved rule.
type RuleOutcome struct {
	ID       string   `json:"id"`
	Admitted bool     `json:"admitted"`
	Reason   string   `json:"reason"`
	Retired  []string `json:"retired,omitempty"` // rules it replaced
}

// RulesPolicy configures rule governance.
type RulesPolicy struct {
	// MinFailures with one label, within FailureWindow, justify a rule.
	MinFailures   int      `json:"min_failures"`
	FailureWindow Duration `json:"failure_window"`
	// RequireEnforcement makes incident rules name the test or check that
	// enforces them (enforced_by).
	RequireEnforcement bool `json:"require_enforcement"`
	// RequireQuote makes requested rules carry the person's words.
	RequireQuote bool `json:"require_quote"`
	// MaxActive caps active rules per scope.
	MaxActive int `json:"max_active"`
	// DuplicateAt is the word-overlap similarity (0..1) at which a rule
	// counts as a duplicate of an active one.
	DuplicateAt float64 `json:"duplicate_at"`
	// StaleAfter flags active rules with no activity for this long.
	StaleAfter Duration `json:"stale_after"`
	// AutoPromote admits a held proposal once enough failures share its label.
	AutoPromote bool `json:"auto_promote"`
	// File is where render writes, relative to the project.
	File string `json:"file"`
	// InContext adds active rules to the session-start context.
	InContext bool `json:"in_context"`
}

// DefaultRulesPolicy is used for unset fields.
func DefaultRulesPolicy() RulesPolicy {
	return RulesPolicy{MinFailures: 2, FailureWindow: Duration(30 * 24 * time.Hour), RequireQuote: true,
		MaxActive: 30, DuplicateAt: 0.6, StaleAfter: Duration(90 * 24 * time.Hour), AutoPromote: true, File: "CLAUDE.md"}
}

type failureRecorded struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Summary string `json:"summary"`
	Ref     string `json:"ref,omitempty"`
}

type ruleProposed struct {
	ID         string        `json:"id"`
	Text       string        `json:"text"`
	Scope      string        `json:"scope,omitempty"`
	Label      string        `json:"label,omitempty"`
	Why        Justification `json:"why"`
	Supersedes []string      `json:"supersedes,omitempty"`
	Source     string        `json:"source,omitempty"`
	Held       string        `json:"held,omitempty"` // the gate's reason when not admitted
}

var labelRe = regexp.MustCompile(`[^a-z0-9._:/-]+`)

func normalizeLabel(s string) string {
	return strings.Trim(labelRe.ReplaceAllString(strings.ToLower(strings.TrimSpace(s)), "-"), "-")
}

// RecordFailure records a failure. With rules.auto_promote, a held proposal
// whose label now has enough failures is admitted; their ids are returned.
func (e *Engine) RecordFailure(in FailureInput) (string, []string, error) {
	p := failureRecorded{ID: newID("fail"), Label: normalizeLabel(in.Label), Summary: strings.TrimSpace(in.Summary), Ref: in.Ref}
	if p.Label == "" || p.Summary == "" {
		return "", nil, errors.New("a failure needs a label and a summary")
	}
	var promoted []string
	_, err := e.write(func(w *wtx) error {
		if _, err := w.emit(evFailureRecorded, p.ID, p); err != nil {
			return err
		}
		if !w.e.Policy.Rules.AutoPromote {
			return nil
		}
		held, err := w.rules(`status = 'proposed' AND label = ?`, p.Label)
		if err != nil {
			return err
		}
		for _, r := range held {
			why := r.Why
			why.Kind = "incident"
			ok, basis, err := w.gate(ruleProposed{ID: r.ID, Text: r.Text, Scope: r.Scope, Label: r.Label, Why: why})
			if err != nil {
				return err
			}
			if ok {
				if _, err := w.emit(evRuleAdmitted, r.ID, statusChange{ID: r.ID, Reason: basis, Cause: p.ID}); err != nil {
					return err
				}
				promoted = append(promoted, r.ID)
			}
		}
		return nil
	})
	return p.ID, promoted, err
}

// ProposeRule records a rule and admits it if its reason holds up.
func (e *Engine) ProposeRule(in RuleInput) (*RuleOutcome, error) {
	p := ruleProposed{ID: newID("rule"), Text: strings.TrimSpace(in.Text), Scope: in.Scope, Label: normalizeLabel(in.Label),
		Why: in.Why, Supersedes: dedupe(in.Supersedes), Source: in.Source}
	if p.Text == "" {
		return nil, errors.New("a rule needs text")
	}
	if p.Scope == "" {
		p.Scope = e.Policy.Scopes.Write
	}
	out := &RuleOutcome{ID: p.ID}
	_, err := e.write(func(w *wtx) error {
		for _, id := range p.Supersedes {
			if err := w.require(id, "rule"); err != nil {
				return err
			}
		}
		for _, f := range p.Why.Failures {
			if err := w.require(f, "fail"); err != nil {
				return err
			}
		}
		ok, reason, err := w.gate(p)
		if err != nil {
			return err
		}
		out.Admitted, out.Reason = ok, reason
		if !ok {
			p.Held = reason
		}
		if _, err := w.emit(evRuleProposed, p.ID, p); err != nil {
			return err
		}
		if !ok {
			return nil
		}
		return w.admit(p.ID, reason, p.Supersedes, out)
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (w *wtx) admit(id, reason string, supersedes []string, out *RuleOutcome) error {
	if _, err := w.emit(evRuleAdmitted, id, statusChange{ID: id, Reason: reason}); err != nil {
		return err
	}
	for _, old := range supersedes {
		if _, err := w.emit(evRuleRetired, old, statusChange{ID: old, Cause: id, Reason: "replaced by " + id}); err != nil {
			return err
		}
		out.Retired = append(out.Retired, old)
	}
	return nil
}

// ApproveRule admits a held proposal on a person's say-so. Duplicates and
// the per-scope cap still apply.
func (e *Engine) ApproveRule(id, by, note string) (*RuleOutcome, error) {
	if strings.TrimSpace(by) == "" {
		return nil, errors.New("approval needs --by: who is approving")
	}
	out := &RuleOutcome{ID: id}
	_, err := e.write(func(w *wtx) error {
		if err := w.require(id, "rule", "proposed"); err != nil {
			return err
		}
		r, err := w.rule(id)
		if err != nil {
			return err
		}
		why := r.Why
		why.Kind, why.By, why.Quote = "approved", by, note
		ok, reason, err := w.gate(ruleProposed{ID: id, Text: r.Text, Scope: r.Scope, Label: r.Label, Why: why})
		if err != nil {
			return err
		}
		out.Admitted, out.Reason = ok, reason
		if !ok {
			return nil
		}
		return w.admit(id, reason, nil, out)
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// MergeRules replaces rules with one. If every rule merged was active, the
// merged rule inherits their standing; otherwise it needs its own reason.
func (e *Engine) MergeRules(ids []string, text string, why Justification) (*RuleOutcome, error) {
	if len(ids) < 2 {
		return nil, errors.New("merge needs at least two rules")
	}
	var scope, label string
	for _, id := range ids {
		r, err := e.Rule(id)
		if err != nil {
			return nil, err
		}
		scope, label = cmp(scope, r.Scope), cmp(label, r.Label)
	}
	if why.Kind == "" {
		why.Kind = "merge"
	}
	return e.ProposeRule(RuleInput{Text: text, Scope: scope, Label: label, Why: why, Supersedes: ids})
}

// RejectRule closes a proposal.
func (e *Engine) RejectRule(id, reason string) error {
	return e.ruleStatus(id, evRuleRejected, reason, "proposed")
}

// RetireRule ends an active rule.
func (e *Engine) RetireRule(id, reason string) error {
	return e.ruleStatus(id, evRuleRetired, reason, "active", "suspect")
}

// ReaffirmRule clears a suspect rule after review.
func (e *Engine) ReaffirmRule(id, note string) error {
	return e.ruleStatus(id, evRuleReaffirmed, note, "suspect")
}

// RuleViolated records that a rule was broken. Rules broken often may be
// unclear or wrong; rationalize lists them.
func (e *Engine) RuleViolated(id, note string) error {
	return e.ruleStatus(id, evRuleViolated, note, "active", "suspect")
}

func (e *Engine) ruleStatus(id, typ, reason string, from ...string) error {
	_, err := e.write(func(w *wtx) error {
		if err := w.require(id, "rule", from...); err != nil {
			return err
		}
		_, err := w.emit(typ, id, statusChange{ID: id, Reason: reason})
		return err
	})
	return err
}

// gate decides whether a rule may be active: a reason that holds up, not a
// duplicate of an active rule, and room under the scope's cap. It returns
// the basis for admitting it, or why it is held.
func (w *wtx) gate(p ruleProposed) (bool, string, error) {
	pol := w.e.Policy.Rules
	basis, held, err := w.justify(p, pol)
	if err != nil || held != "" {
		return false, held, err
	}
	active, err := w.rules(`status IN ('active', 'suspect') AND scope = ?`, p.Scope)
	if err != nil {
		return false, "", err
	}
	replacing := 0
	for _, r := range active {
		if contains(p.Supersedes, r.ID) {
			replacing++
			continue
		}
		if sim := similarity(p.Text, r.Text); sim >= pol.DuplicateAt {
			return false, fmt.Sprintf("duplicates %s (similarity %.2f): supersede or merge it instead", r.ID, sim), nil
		}
	}
	if pol.MaxActive > 0 && len(active)-replacing >= pol.MaxActive {
		return false, fmt.Sprintf("scope %q already has %d active rules (rules.max_active %d): retire or merge some first",
			p.Scope, len(active)-replacing, pol.MaxActive), nil
	}
	return true, basis, nil
}

func (w *wtx) justify(p ruleProposed, pol RulesPolicy) (basis, held string, err error) {
	why := p.Why
	switch why.Kind {
	case "requested", "approved":
		if strings.TrimSpace(why.By) == "" {
			return "", "a requested rule needs who asked for it (by)", nil
		}
		if why.Kind == "requested" && pol.RequireQuote && strings.TrimSpace(why.Quote) == "" {
			return "", "a requested rule needs the person's words (quote)", nil
		}
		return why.Kind + " by " + why.By, "", nil
	case "decision":
		if why.Decision == "" {
			return "", "a decision rule needs the decision id", nil
		}
		if err := w.require(why.Decision, "dec", "active"); err != nil {
			return "", err.Error(), nil //nolint:nilerr // an inactive decision is a reason to hold the rule, not a failure
		}
		return "carries out " + why.Decision, "", nil
	case "incident":
		if p.Label == "" {
			return "", "an incident rule needs the failure label it addresses", nil
		}
		ids, err := selectAll(w.tx, func(s scanner) (string, error) {
			var id string
			return id, s.Scan(&id)
		}, `SELECT id FROM failures WHERE label = ? AND at > ?`, p.Label, ms(w.e.Now().Add(-pol.FailureWindow.D())))
		if err != nil {
			return "", "", err
		}
		n := len(dedupe(append(ids, why.Failures...)))
		if n < pol.MinFailures {
			return "", fmt.Sprintf("only %d failure(s) labeled %q in the last %s; rules.min_failures is %d",
				n, p.Label, pol.FailureWindow.D(), pol.MinFailures), nil
		}
		if pol.RequireEnforcement && why.EnforcedBy == "" {
			return "", "an incident rule needs enforced_by: the test or check that now catches this", nil
		}
		basis := fmt.Sprintf("after %d %q failures", n, p.Label)
		if why.EnforcedBy != "" {
			basis += "; enforced by " + why.EnforcedBy
		}
		return basis, "", nil
	case "merge":
		for _, id := range p.Supersedes {
			r, err := w.rule(id)
			if err != nil {
				return "", "", err
			}
			if r.Status != "active" && r.Status != "suspect" {
				return "", fmt.Sprintf("%s is %s; a merge inherits standing only from active rules", id, r.Status), nil
			}
		}
		return "merge of " + strings.Join(p.Supersedes, ", "), "", nil
	}
	return "", "no reason given: a rule needs an explicit request (requested, by, quote), repeated failures " +
		"(incident, label), or a decision (decision)", nil
}

// --- reading ---------------------------------------------------------------

const ruleCols = `id, text, scope, label, status, why, basis, held, source, proposed_at, admitted_at, retired_at,
	superseded_by, violations, last_activity, actor`

func scanRule(s scanner) (Rule, error) {
	var r Rule
	var why string
	var proposed, last int64
	var admitted, retired sql.NullInt64
	err := s.Scan(&r.ID, &r.Text, &r.Scope, &r.Label, &r.Status, &why, &r.Basis, &r.Held, &r.Source, &proposed,
		&admitted, &retired, &r.SupersededBy, &r.Violations, &last, &r.Actor)
	_ = json.Unmarshal([]byte(why), &r.Why) // projected from a verified event; empty if absent
	r.ProposedAt, r.LastActivity, r.AdmittedAt, r.RetiredAt = fromMs(proposed), fromMs(last), optTime(admitted), optTime(retired)
	return r, err
}

func (w *wtx) rules(where string, args ...any) ([]Rule, error) {
	return selectAll(w.tx, scanRule, `SELECT `+ruleCols+` FROM rules WHERE `+where+` ORDER BY proposed_at`, args...)
}

func (w *wtx) rule(id string) (Rule, error) {
	return scanRule(w.tx.QueryRow(`SELECT `+ruleCols+` FROM rules WHERE id = ?`, id))
}

// Rule loads one rule.
func (e *Engine) Rule(id string) (Rule, error) {
	r, err := scanRule(e.db.QueryRow(`SELECT `+ruleCols+` FROM rules WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return r, fmt.Errorf("no such rule %s", id)
	}
	return r, err
}

// Rules lists rules with a status ("" for all), visible under scopes.read.
func (e *Engine) Rules(status string) ([]Rule, error) {
	q, args := `1 = 1`, []any{}
	if status != "" {
		q, args = `status = ?`, []any{status}
	}
	rs, err := selectAll(e.db, scanRule, `SELECT `+ruleCols+` FROM rules WHERE `+q+` ORDER BY proposed_at`, args...)
	if err != nil {
		return nil, err
	}
	out := rs[:0]
	for _, r := range rs {
		if e.visible(r.Scope) {
			out = append(out, r)
		}
	}
	return out, nil
}

// Failures lists failures, newest first, optionally for one label.
func (e *Engine) Failures(label string, limit int) ([]Failure, error) {
	q, args := `1 = 1`, []any{}
	if label != "" {
		q, args = `label = ?`, []any{normalizeLabel(label)}
	}
	if limit <= 0 {
		limit = 50
	}
	return selectAll(e.db, func(s scanner) (Failure, error) {
		var f Failure
		var at int64
		err := s.Scan(&f.ID, &f.Label, &f.Summary, &f.Ref, &at, &f.Actor, &f.Session)
		f.At = fromMs(at)
		return f, err
	}, `SELECT id, label, summary, ref, at, actor, session FROM failures WHERE `+q+` ORDER BY at DESC LIMIT ?`, append(args, limit)...)
}

// --- rationalize -------------------------------------------------------------

// RulePair is two rules that look like the same rule.
type RulePair struct {
	A          Rule    `json:"a"`
	B          Rule    `json:"b"`
	Similarity float64 `json:"similarity"`
	JudgedBy   string  `json:"judged_by,omitempty"` // set when a judge, not word overlap, found it
}

// RuleCount pairs a rule with a count.
type RuleCount struct {
	Rule  Rule `json:"rule"`
	Count int  `json:"count"`
}

// RulesReport is what rationalize found.
type RulesReport struct {
	Duplicates  []RulePair  `json:"duplicates"`
	Held        []Rule      `json:"held"`        // proposals without a reason that holds up
	Promotable  []Rule      `json:"promotable"`  // held proposals that would now pass the gate
	Suspect     []Rule      `json:"suspect"`     // what they rest on changed
	Ineffective []RuleCount `json:"ineffective"` // failures with their label since they were admitted
	Violated    []RuleCount `json:"violated"`
	Stale       []Rule      `json:"stale"`
	OverCap     []string    `json:"over_cap"` // scopes at or over rules.max_active
	Notes       []string    `json:"notes,omitempty"`
}

// RationalizeRules reviews every rule. With judges, rule pairs that share
// some words but not enough to count as duplicates are asked whether they
// require the same behavior.
func (e *Engine) RationalizeRules(ctx context.Context, useJudges bool) (*RulesReport, error) {
	pol := e.Policy.Rules
	rep := &RulesReport{}
	all, err := e.Rules("")
	if err != nil {
		return nil, err
	}
	var live []Rule
	byScope := map[string]int{}
	now := e.Now()
	for _, r := range all {
		switch r.Status {
		case "proposed":
			rep.Held = append(rep.Held, r)
			live = append(live, r)
		case "suspect":
			rep.Suspect = append(rep.Suspect, r)
			live = append(live, r)
			byScope[r.Scope]++
		case "active":
			live = append(live, r)
			byScope[r.Scope]++
			if r.Label != "" && r.AdmittedAt != nil {
				var n int
				if err := e.db.QueryRow(`SELECT COUNT(*) FROM failures WHERE label = ? AND at > ?`, r.Label, ms(*r.AdmittedAt)).Scan(&n); err != nil {
					return nil, err
				}
				if n > 0 {
					rep.Ineffective = append(rep.Ineffective, RuleCount{r, n})
				}
			}
			if r.Violations > 0 {
				rep.Violated = append(rep.Violated, RuleCount{r, r.Violations})
			}
			if pol.StaleAfter > 0 && now.Sub(r.LastActivity) > pol.StaleAfter.D() {
				rep.Stale = append(rep.Stale, r)
			}
		}
	}
	for scope, n := range byScope {
		if pol.MaxActive > 0 && n >= pol.MaxActive {
			rep.OverCap = append(rep.OverCap, fmt.Sprintf("%s: %d active (max %d)", cmp(scope, "(no scope)"), n, pol.MaxActive))
		}
	}
	sort.Strings(rep.OverCap)

	// Which held proposals would pass now (as incidents, if labeled)?
	_, err = e.write(func(w *wtx) error {
		for _, r := range rep.Held {
			why := r.Why
			if r.Label != "" && why.Kind == "" || why.Kind == "imported" {
				why.Kind = "incident"
			}
			if ok, _, err := w.gate(ruleProposed{ID: r.ID, Text: r.Text, Scope: r.Scope, Label: r.Label, Why: why}); err != nil {
				return err
			} else if ok {
				rep.Promotable = append(rep.Promotable, r)
			}
		}
		return errRollback
	})
	if err != nil && !errors.Is(err, errRollback) {
		return nil, err
	}

	var maybe []RulePair
	for i := range live {
		for j := i + 1; j < len(live); j++ {
			a, b := live[i], live[j]
			if a.Scope != b.Scope {
				continue
			}
			sim := similarity(a.Text, b.Text)
			switch {
			case sim >= pol.DuplicateAt:
				rep.Duplicates = append(rep.Duplicates, RulePair{A: a, B: b, Similarity: round3(sim)})
			case sim > 0: // paraphrases can share as little as one word
				maybe = append(maybe, RulePair{A: a, B: b, Similarity: round3(sim)})
			}
		}
	}
	if useJudges && len(e.Judges.Stages) > 0 && len(maybe) > 0 {
		sort.Slice(maybe, func(i, j int) bool { return maybe[i].Similarity > maybe[j].Similarity })
		const maxPairs = 15
		if len(maybe) > maxPairs {
			rep.Notes = append(rep.Notes, fmt.Sprintf("asked judges about the %d most similar of %d candidate pairs", maxPairs, len(maybe)))
			maybe = maybe[:maxPairs]
		}
		for _, pair := range maybe {
			same, by, err := e.sameRule(ctx, pair.A.Text, pair.B.Text)
			if err != nil {
				rep.Notes = append(rep.Notes, "judge: "+err.Error())
				break
			}
			if same {
				pair.JudgedBy = by
				rep.Duplicates = append(rep.Duplicates, pair)
			}
		}
	}
	return rep, nil
}

var errRollback = errors.New("rollback")

var sameRuleQuestion = judge.Question{ID: "same_rule", Kind: judge.Probability,
	Instructions: "Do these two rules for an AI agent require the same behavior, so that keeping one would make the other redundant?",
	True:         "Following either rule means following the other; one can replace both",
	False:        "They require different things, or one covers cases the other doesn't"}

func (e *Engine) sameRule(ctx context.Context, a, b string) (bool, string, error) {
	req := judge.Request{Purpose: "Find duplicate agent rules.", Questions: []judge.Question{sameRuleQuestion},
		State: map[string]any{"rule_a": e.redactor.Redact(a), "rule_b": e.redactor.Redact(b)}}
	out := e.Judges.Ask(ctx, req, func(r *judge.Result) bool { return r.Answers["same_rule"].Confidence >= 0.8 })
	if out.Final == nil {
		if len(out.Errors) > 0 {
			return false, "", errors.New(out.Errors[0])
		}
		return false, "", nil
	}
	return out.Final.Answers["same_rule"].Probability >= 0.8, out.Final.Judge, nil
}

var stopwords = map[string]bool{"a": true, "an": true, "the": true, "to": true, "of": true, "and": true, "or": true,
	"in": true, "on": true, "for": true, "with": true, "is": true, "are": true, "be": true, "it": true, "that": true,
	"this": true, "you": true, "your": true, "we": true, "our": true, "as": true, "at": true, "by": true, "any": true}

func ruleWords(s string) map[string]bool {
	out := map[string]bool{}
	for _, w := range wordRe.FindAllString(strings.ToLower(s), -1) {
		if !stopwords[w] {
			out[strings.TrimSuffix(w, "s")] = true
		}
	}
	return out
}

// similarity is the Jaccard overlap of two rules' words.
func similarity(a, b string) float64 {
	wa, wb := ruleWords(a), ruleWords(b)
	if len(wa) == 0 || len(wb) == 0 {
		return 0
	}
	inter := 0
	for w := range wa {
		if wb[w] {
			inter++
		}
	}
	return float64(inter) / float64(len(wa)+len(wb)-inter)
}

func round3(x float64) float64 { return float64(int(x*1000+0.5)) / 1000 }

// --- import and render ---------------------------------------------------------

const (
	rulesStart = "<!-- smem:rules:start -->"
	rulesEnd   = "<!-- smem:rules:end -->"
)

var (
	bulletRe     = regexp.MustCompile(`^\s*(?:[-*+]|\d+[.)])\s+(.+)$`)
	imperativeRe = regexp.MustCompile(`(?i)\b(always|never|must|don't|do not|should|avoid|prefer|only)\b`)
)

// ImportRules reads rules written by hand or by agents (CLAUDE.md,
// AGENTS.md, .claude/rules/*.md) and records each as a proposal with its
// source, so rationalize can sort them out. Nothing is admitted: imported
// text has no recorded reason. Text already recorded as a rule is skipped.
func (e *Engine) ImportRules(paths []string) ([]string, error) {
	existing := map[string]bool{}
	all, err := e.Rules("")
	if err != nil {
		return nil, err
	}
	for _, r := range all {
		existing[strings.ToLower(strings.Join(strings.Fields(r.Text), " "))] = true
	}
	var ids []string
	for _, path := range paths {
		cands, err := readRuleCandidates(path)
		if err != nil {
			return ids, err
		}
		for _, c := range cands {
			key := strings.ToLower(strings.Join(strings.Fields(c.text), " "))
			if existing[key] {
				continue
			}
			existing[key] = true
			out, err := e.ProposeRule(RuleInput{Text: c.text, Why: Justification{Kind: "imported"}, Source: fmt.Sprintf("%s:%d", path, c.line)})
			if err != nil {
				return ids, err
			}
			ids = append(ids, out.ID)
		}
	}
	return ids, nil
}

type candidate struct {
	text string
	line int
}

func readRuleCandidates(path string) ([]candidate, error) {
	f, err := os.Open(path) //nolint:gosec // a file the user named to import
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only
	var out []candidate
	var cur *candidate
	flush := func() {
		if cur != nil && len(cur.text) >= 12 {
			out = append(out, *cur)
		}
		cur = nil
	}
	sc := bufio.NewScanner(f)
	inFence, inBlock := false, false
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		trim := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trim, "```"):
			flush()
			inFence = !inFence
			continue
		case trim == rulesStart:
			flush()
			inBlock = true
			continue
		case trim == rulesEnd:
			inBlock = false
			continue
		}
		if inFence || inBlock {
			continue
		}
		if m := bulletRe.FindStringSubmatch(line); m != nil {
			flush()
			cur = &candidate{text: strings.TrimSpace(m[1]), line: n}
			continue
		}
		if trim == "" || strings.HasPrefix(trim, "#") || strings.HasPrefix(trim, "<!--") {
			flush()
			continue
		}
		if cur != nil && (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")) {
			cur.text += " " + trim
			continue
		}
		flush()
		if imperativeRe.MatchString(trim) {
			cur = &candidate{text: trim, line: n}
		}
	}
	flush()
	return out, sc.Err()
}

// RulesBlock renders active rules visible under scopes.read as markdown.
func (e *Engine) RulesBlock() (string, error) {
	rs, err := e.Rules("active")
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(rulesStart + "\n")
	b.WriteString("## Rules\n\n")
	b.WriteString("Managed by smem: each rule has a recorded reason (`smem why <rule-id>`). " +
		"Change them with `smem rules`, not by editing this block.\n\n")
	if len(rs) == 0 {
		b.WriteString("(no active rules)\n")
	}
	for _, r := range rs {
		fmt.Fprintf(&b, "- %s (%s: %s)\n", oneLine(r.Text, 400), r.ID, r.Basis)
	}
	b.WriteString(rulesEnd + "\n")
	return b.String(), nil
}

// RenderRules writes the rules block into file, replacing an earlier block
// and leaving everything else alone. It reports whether the file changed;
// with check, it changes nothing.
func (e *Engine) RenderRules(file string, check bool) (bool, error) {
	if file == "" {
		file = cmp(e.Policy.Rules.File, "CLAUDE.md")
	}
	if !filepath.IsAbs(file) {
		file = filepath.Join(filepath.Dir(filepath.Dir(e.path)), file)
	}
	block, err := e.RulesBlock()
	if err != nil {
		return false, err
	}
	old, err := os.ReadFile(file) //nolint:gosec // the rules file the user configured
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	text := string(old)
	var next string
	if i, j := strings.Index(text, rulesStart), strings.Index(text, rulesEnd); i >= 0 && j > i {
		end := j + len(rulesEnd)
		if end < len(text) && text[end] == '\n' {
			end++
		}
		next = text[:i] + block + text[end:]
	} else {
		sep := ""
		if text != "" && !strings.HasSuffix(text, "\n\n") {
			sep = "\n"
			if !strings.HasSuffix(text, "\n") {
				sep = "\n\n"
			}
		}
		next = text + sep + block
	}
	if next == text {
		return false, nil
	}
	if check {
		return true, nil
	}
	return true, os.WriteFile(file, []byte(next), 0o644) //nolint:gosec // CLAUDE.md is a shared project file
}

// rulesContext is the rules section of the session context.
func (e *Engine) rulesContext() (string, error) {
	if !e.Policy.Rules.InContext {
		return "", nil
	}
	rs, err := e.Rules("active")
	if err != nil || len(rs) == 0 {
		return "", err
	}
	var b strings.Builder
	b.WriteString("\n## smem: rules\n")
	for _, r := range rs {
		fmt.Fprintf(&b, "- [%s] %s\n", r.ID, oneLine(r.Text, 300))
	}
	return b.String(), nil
}

// --- projection ------------------------------------------------------------------

func applyRuleEvent(a *applier, ev Event, decode func(any) bool) {
	switch ev.Type {
	case evFailureRecorded:
		var p failureRecorded
		if decode(&p) {
			a.exec(`INSERT INTO failures (id, label, summary, ref, at, actor, session, event) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
				p.ID, p.Label, p.Summary, p.Ref, a.at, ev.Actor, ev.Session, ev.ID)
		}
	case evRuleProposed:
		var p ruleProposed
		if !decode(&p) {
			return
		}
		why, _ := json.Marshal(p.Why)
		a.exec(`INSERT INTO rules (id, text, scope, label, status, why, held, source, proposed_at, last_activity, actor, session, event)
			VALUES (?, ?, ?, ?, 'proposed', ?, ?, ?, ?, ?, ?, ?, ?)`,
			p.ID, p.Text, p.Scope, p.Label, string(why), p.Held, p.Source, a.at, a.at, ev.Actor, ev.Session, ev.ID)
		for _, f := range p.Why.Failures {
			a.edge(p.ID, f, "justified_by")
		}
		if p.Why.Decision != "" {
			a.edge(p.ID, p.Why.Decision, "justified_by")
		}
		for _, s := range p.Supersedes {
			a.edge(p.ID, s, "supersedes")
		}
		a.status(p.ID, "proposed", "", p.Held)
	case evRuleAdmitted:
		var p statusChange
		if decode(&p) {
			a.exec(`UPDATE rules SET status = 'active', basis = ?, held = '', admitted_at = ?, last_activity = ? WHERE id = ?`,
				p.Reason, a.at, a.at, p.ID)
			a.status(p.ID, "admitted", p.Cause, p.Reason)
		}
	case evRuleRejected:
		var p statusChange
		if decode(&p) {
			a.exec(`UPDATE rules SET status = 'rejected', retired_at = ? WHERE id = ?`, a.at, p.ID)
			a.status(p.ID, "rejected", "", p.Reason)
		}
	case evRuleRetired:
		var p statusChange
		if decode(&p) {
			a.exec(`UPDATE rules SET status = 'retired', retired_at = ?, superseded_by = ? WHERE id = ?`, a.at, p.Cause, p.ID)
			a.status(p.ID, "retired", p.Cause, p.Reason)
		}
	case evRuleSuspected:
		var p statusChange
		if decode(&p) {
			a.exec(`UPDATE rules SET status = 'suspect' WHERE id = ? AND status = 'active'`, p.ID)
			a.status(p.ID, "suspected", p.Cause, p.Reason)
		}
	case evRuleReaffirmed:
		var p statusChange
		if decode(&p) {
			a.exec(`UPDATE rules SET status = 'active', last_activity = ? WHERE id = ? AND status = 'suspect'`, a.at, p.ID)
			a.status(p.ID, "reaffirmed", "", p.Reason)
		}
	case evRuleViolated:
		var p statusChange
		if decode(&p) {
			a.exec(`UPDATE rules SET violations = violations + 1, last_activity = ? WHERE id = ?`, a.at, p.ID)
			a.status(p.ID, "violated", "", p.Reason)
		}
	}
}

const rulesSchema = `
CREATE TABLE IF NOT EXISTS rules (
	id TEXT PRIMARY KEY, text TEXT NOT NULL, scope TEXT NOT NULL DEFAULT '', label TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL, why TEXT NOT NULL DEFAULT '{}', basis TEXT NOT NULL DEFAULT '', held TEXT NOT NULL DEFAULT '',
	source TEXT NOT NULL DEFAULT '', proposed_at INTEGER NOT NULL, admitted_at INTEGER, retired_at INTEGER,
	superseded_by TEXT NOT NULL DEFAULT '', violations INTEGER NOT NULL DEFAULT 0, last_activity INTEGER NOT NULL,
	actor TEXT NOT NULL DEFAULT '', session TEXT NOT NULL DEFAULT '', event TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS rules_status ON rules(status, scope);
CREATE TABLE IF NOT EXISTS failures (
	id TEXT PRIMARY KEY, label TEXT NOT NULL, summary TEXT NOT NULL, ref TEXT NOT NULL DEFAULT '',
	at INTEGER NOT NULL, actor TEXT NOT NULL DEFAULT '', session TEXT NOT NULL DEFAULT '', event TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS failures_label ON failures(label, at);
`
