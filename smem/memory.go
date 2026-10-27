package smem

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Memory kinds and how fast each one's salience decays (the ACT-R decay
// exponent d; larger fades faster).
var decayByKind = map[string]float64{
	"episode":    0.8, // what happened; fades fast unless consolidated
	"fact":       0.5,
	"insight":    0.4,
	"procedure":  0.3, // how to work
	"preference": 0.3,
}

var defaultVolatility = map[string]string{
	"episode": "stable", "fact": "normal", "insight": "normal", "procedure": "stable", "preference": "stable",
}

// halfLives is how long until confidence in an unchecked memory halves.
// Volatility is about whether the world changes, not about relevance.
var halfLives = map[string]time.Duration{
	"volatile":  24 * time.Hour,
	"normal":    30 * 24 * time.Hour,
	"stable":    365 * 24 * time.Hour,
	"permanent": 0, // never decays
}

// MemoryInput describes a new memory.
type MemoryInput struct {
	Kind       string // fact | episode | procedure | preference | insight
	Content    string
	Scope      string    // free-form: "user", "project:x", "agent:y"
	Volatility string    // volatile | normal | stable | permanent
	Confidence float64   // 0..1, default 0.8
	ValidFrom  time.Time // when it became true in the world; zero = now
	// DerivedFrom lists the memories, decisions and sources this came from.
	// Free references (file paths, URLs, commits) are captured as sources.
	DerivedFrom []string
}

// Memory is one immutable version of a memory. A changed fact is a new
// Memory that supersedes this one; the id is therefore also the version.
type Memory struct {
	ID           string     `json:"id"`
	Kind         string     `json:"kind"`
	Content      string     `json:"content"`
	Scope        string     `json:"scope,omitempty"`
	Volatility   string     `json:"volatility"`
	Status       string     `json:"status"`
	Confidence0  float64    `json:"confidence0"`
	ValidFrom    time.Time  `json:"valid_from"`
	ValidTo      *time.Time `json:"valid_to,omitempty"`
	RecordedAt   time.Time  `json:"recorded_at"`
	ClosedAt     *time.Time `json:"closed_at,omitempty"`
	RetractedAt  *time.Time `json:"retracted_at,omitempty"`
	ArchivedAt   *time.Time `json:"archived_at,omitempty"`
	Supersedes   string     `json:"supersedes,omitempty"`
	SupersededBy string     `json:"superseded_by,omitempty"`
	Actor        string     `json:"actor"`
	Session      string     `json:"session,omitempty"`
}

const memoryCols = `id, kind, content, scope, volatility, status, confidence0, valid_from, valid_to, recorded_at,
	closed_at, retracted_at, archived_at, supersedes, superseded_by, actor, session`

func scanMemory(s scanner) (Memory, error) {
	var m Memory
	var vf, ra int64
	var vt, ca, rt, aa sql.NullInt64
	err := s.Scan(&m.ID, &m.Kind, &m.Content, &m.Scope, &m.Volatility, &m.Status, &m.Confidence0, &vf, &vt, &ra,
		&ca, &rt, &aa, &m.Supersedes, &m.SupersededBy, &m.Actor, &m.Session)
	m.ValidFrom, m.RecordedAt = fromMs(vf), fromMs(ra)
	m.ValidTo, m.ClosedAt, m.RetractedAt, m.ArchivedAt = optTime(vt), optTime(ca), optTime(rt), optTime(aa)
	return m, err
}

// Flag reports a record marked suspect by propagation.
type Flag struct {
	Subject string `json:"subject"`
	Status  string `json:"status"`
	Cause   string `json:"cause"`
	Root    string `json:"root"`
	Reason  string `json:"reason,omitempty"`
}

func flagsFrom(evs []Event) []Flag {
	var out []Flag
	for _, ev := range evs {
		if ev.Type != evDecisionSuspected && ev.Type != evMemorySuspected && ev.Type != evRuleSuspected {
			continue
		}
		var p statusChange
		_ = json.Unmarshal(ev.Payload, &p) // our own event, just written
		out = append(out, Flag{Subject: p.ID, Status: "suspect", Cause: p.Cause, Root: p.Root, Reason: p.Reason})
	}
	return out
}

func normalizeMemory(in *MemoryInput) error {
	in.Content = strings.TrimSpace(in.Content)
	if in.Content == "" {
		return fmt.Errorf("memory content is empty")
	}
	if in.Kind == "" {
		in.Kind = "fact"
	}
	if _, ok := decayByKind[in.Kind]; !ok {
		return fmt.Errorf("unknown kind %q (want one of %s)", in.Kind, keysOf(decayByKind))
	}
	if in.Volatility == "" {
		in.Volatility = defaultVolatility[in.Kind]
	}
	if _, ok := halfLives[in.Volatility]; !ok {
		return fmt.Errorf("unknown volatility %q (want one of %s)", in.Volatility, keysOf(halfLives))
	}
	if in.Confidence == 0 {
		in.Confidence = 0.8
	}
	if in.Confidence < 0 || in.Confidence > 1 {
		return fmt.Errorf("confidence must be between 0 and 1")
	}
	return nil
}

func keysOf[V any](m map[string]V) string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return strings.Join(ks, ", ")
}

// Remember records a new memory.
func (e *Engine) Remember(in MemoryInput) (string, error) {
	id, _, err := e.assert(in, "")
	return id, err
}

// Supersede records a new version of a memory. The old version stops being
// valid when the new one starts, and anything that relied on the old version
// is marked suspect.
func (e *Engine) Supersede(old string, in MemoryInput) (string, []Flag, error) {
	return e.assert(in, old)
}

func (e *Engine) assert(in MemoryInput, supersedes string) (string, []Flag, error) {
	if in.Scope == "" {
		in.Scope = e.Policy.Scopes.Write
	}
	if err := normalizeMemory(&in); err != nil {
		return "", nil, err
	}
	p := memoryAsserted{ID: newID("mem"), Kind: in.Kind, Content: in.Content, Scope: in.Scope,
		Volatility: in.Volatility, Confidence: in.Confidence, Supersedes: supersedes}
	if !in.ValidFrom.IsZero() {
		p.ValidFrom = ms(in.ValidFrom)
	}
	evs, err := e.write(func(w *wtx) error {
		for _, ref := range dedupe(in.DerivedFrom) {
			if isRecordID(ref) {
				if _, _, err := w.lookup(ref); err != nil {
					return err
				}
				p.DerivedFrom = append(p.DerivedFrom, ref)
				continue
			}
			src := sourceCaptured{ID: newID("src"), Kind: w.e.sourceKind(ref), Ref: ref}
			if _, err := w.emit(evSourceCaptured, src.ID, src); err != nil {
				return err
			}
			p.DerivedFrom = append(p.DerivedFrom, src.ID)
		}
		if supersedes != "" {
			if err := w.require(supersedes, "mem", "active", "suspect"); err != nil {
				return err
			}
		}
		if _, err := w.emit(evMemoryAsserted, p.ID, p); err != nil {
			return err
		}
		if supersedes != "" {
			return w.propagate(supersedes, "superseded by "+p.ID)
		}
		return nil
	})
	return p.ID, flagsFrom(evs), err
}

// Invalidate records that a memory stopped being true at validTo (zero =
// now): the world changed. Dependents are marked suspect.
func (e *Engine) Invalidate(id, reason string, validTo time.Time) ([]Flag, error) {
	p := statusChange{ID: id, Reason: reason}
	if !validTo.IsZero() {
		p.ValidTo = ms(validTo)
	}
	return e.closeMemory(evMemoryInvalidated, p)
}

// Retract records that a memory was never true: the belief was wrong.
// Queries "as known at" a time after the retraction no longer see it.
func (e *Engine) Retract(id, reason string) ([]Flag, error) {
	return e.closeMemory(evMemoryRetracted, statusChange{ID: id, Reason: reason})
}

func (e *Engine) closeMemory(typ string, p statusChange) ([]Flag, error) {
	evs, err := e.write(func(w *wtx) error {
		if err := w.require(p.ID, "mem", "active", "suspect", "archived"); err != nil {
			return err
		}
		if _, err := w.emit(typ, p.ID, p); err != nil {
			return err
		}
		return w.propagate(p.ID, p.Reason)
	})
	return flagsFrom(evs), err
}

// Reconfirm records that a memory was checked and still holds. It resets the
// confidence clock and clears a suspect flag. confidence 0 keeps the old value.
func (e *Engine) Reconfirm(id string, confidence float64, note string) error {
	if confidence < 0 || confidence > 1 {
		return fmt.Errorf("confidence must be between 0 and 1")
	}
	_, err := e.write(func(w *wtx) error {
		if err := w.require(id, "mem", "active", "suspect", "archived"); err != nil {
			return err
		}
		_, err := w.emit(evMemoryReconfirmed, id, statusChange{ID: id, Confidence: confidence, Reason: note})
		return err
	})
	return err
}

// Signal records feedback about a memory: used, confirmed or contradicted.
func (e *Engine) Signal(id, signal, note string) error {
	switch signal {
	case "used", "confirmed", "contradicted":
	default:
		return fmt.Errorf("signal must be used, confirmed or contradicted")
	}
	_, err := e.write(func(w *wtx) error {
		if err := w.require(id, "mem"); err != nil {
			return err
		}
		p := memorySignal{ID: id, Signal: signal, Note: note}
		if signal == "confirmed" {
			// The boost goes in the event, so every replica projects the
			// same confidence whatever its own config says.
			p.Boost = w.e.Policy.Confidence.ConfirmBoost
		}
		_, err := w.emit(evMemorySignal, id, p)
		return err
	})
	return err
}

// propagate marks records that depend on root as suspect, PropagationDepth
// hops out. Only records that are currently active are flagged, so running it
// twice for the same cause is harmless.
func (w *wtx) propagate(root, reason string) error {
	depth := w.e.PropagationDepth
	if depth < 1 {
		depth = 1
	}
	frontier := []string{root}
	for level := 0; level < depth && len(frontier) > 0; level++ {
		var next []string
		for _, cause := range frontier {
			deps, err := w.dependents(cause)
			if err != nil {
				return err
			}
			for _, d := range deps {
				typ := evDecisionSuspected
				switch {
				case strings.HasPrefix(d, "mem-"):
					typ = evMemorySuspected
				case strings.HasPrefix(d, "rule-"):
					typ = evRuleSuspected
				}
				if _, err := w.emit(typ, d, statusChange{ID: d, Cause: cause, Root: root, Reason: reason}); err != nil {
					return err
				}
				next = append(next, d)
			}
		}
		frontier = next
	}
	return nil
}

// dependents returns active records that rely directly on id: decisions that
// used it or rest on it as an assumption, and memories derived from it.
func (w *wtx) dependents(id string) ([]string, error) {
	rows, err := w.tx.Query(`
		SELECT d.id FROM edges e JOIN decisions d ON d.id = e.src
			WHERE e.dst = ? AND e.type = 'used' AND d.status = 'active'
		UNION
		SELECT d.id FROM assumptions a JOIN decisions d ON d.id = a.decision_id
			WHERE a.id = ? AND d.status = 'active'
		UNION
		SELECT m.id FROM edges e JOIN memories m ON m.id = e.src
			WHERE e.dst = ? AND e.type = 'derived_from' AND m.status = 'active'
		UNION
		SELECT r.id FROM edges e JOIN rules r ON r.id = e.src
			WHERE e.dst = ? AND e.type = 'justified_by' AND r.status = 'active'
		ORDER BY 1`, id, id, id, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// Memory loads one memory by id.
func (e *Engine) Memory(id string) (Memory, error) {
	m, err := scanMemory(e.db.QueryRow(`SELECT `+memoryCols+` FROM memories WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return m, fmt.Errorf("no such memory %s", id)
	}
	return m, err
}
