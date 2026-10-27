package judge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Jev calls TypeSafe's Jev judgment model, directly or through OpenRouter.
// Both speak the same {state, questions} → {answers} contract.
type Jev struct {
	BaseURL string
	APIKey  string
	Model   string
	HTTP    *http.Client
	Retry   Retry
	Limit   Limiter
	path    string
}

// NewJev returns a client for TypeSafe's API (TYPESAFE_API_KEY).
func NewJev(apiKey string) *Jev {
	return &Jev{BaseURL: "https://api.typesafe.ai", APIKey: apiKey, Model: "jev-latest",
		HTTP: &http.Client{Timeout: 60 * time.Second}, Limit: NewLimiter(2), path: "/v1/systemone"}
}

// NewJevOpenRouter returns a client for Jev through OpenRouter's Decisions API.
func NewJevOpenRouter(apiKey string) *Jev {
	return &Jev{BaseURL: "https://openrouter.ai/api", APIKey: apiKey, Model: "~typesafe/jev-latest",
		HTTP: &http.Client{Timeout: 60 * time.Second}, Limit: NewLimiter(2), path: "/alpha/decisions"}
}

// Name implements Judge.
func (j *Jev) Name() string { return "jev" }

type jevAnswer struct {
	Type          string             `json:"type"`
	Choice        string             `json:"choice"`
	Score         *int               `json:"score"`
	Noul          *float64           `json:"noul"`
	Probabilities map[string]float64 `json:"probabilities"`
	Confidence    *float64           `json:"confidence"`
}

type jevResponse struct {
	Answers map[string]jevAnswer `json:"answers"`
	Usage   struct {
		InputTokens  int64 `json:"input_tokens"`
		OutputTokens int64 `json:"output_tokens"`
	} `json:"usage"`
	Model string `json:"model"`
}

func jevQuestion(q Question) map[string]any {
	instr := q.Instructions + antiInjection
	switch q.Kind {
	case Choice:
		criteria := map[string]any{}
		for _, l := range q.Labels {
			criteria[l.Key] = l.Description
		}
		return map[string]any{"type": "choice", "instructions": instr, "criteria": criteria}
	case Score:
		levels := make([]any, len(q.Labels))
		for i, l := range q.Labels {
			levels[i] = l.Description
		}
		return map[string]any{"type": "score", "instructions": instr, "criteria": levels}
	default:
		criteria := map[string]any{}
		if q.True != "" {
			criteria["true"] = q.True
		}
		if q.False != "" {
			criteria["false"] = q.False
		}
		m := map[string]any{"type": "noul", "instructions": instr}
		if len(criteria) > 0 {
			m["criteria"] = criteria
		}
		return m
	}
}

// Ask implements Judge.
func (j *Jev) Ask(ctx context.Context, req Request) (*Result, error) {
	questions := map[string]any{}
	for _, q := range req.Questions {
		questions[q.ID] = jevQuestion(q)
	}
	body, err := json.Marshal(map[string]any{
		"model":     j.Model,
		"state":     map[string]any{"purpose": req.Purpose, "data": req.State},
		"questions": questions,
	})
	if err != nil {
		return nil, err
	}
	raw, err := j.post(ctx, body)
	if err != nil {
		return nil, err
	}
	var resp jevResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("jev: unparseable response")
	}
	res := &Result{Judge: j.Name(), Model: resp.Model, Calibrated: true, Answers: map[string]Answer{},
		Usage: Usage{InputTokens: resp.Usage.InputTokens, OutputTokens: resp.Usage.OutputTokens}}
	if res.Model == "" {
		res.Model = j.Model
	}
	for _, q := range req.Questions {
		ja, ok := resp.Answers[q.ID]
		if !ok {
			continue // checkAll reports the missing answer
		}
		a := Answer{Kind: q.Kind, Probabilities: ja.Probabilities}
		switch q.Kind {
		case Choice:
			a.Choice = ja.Choice
			a.Confidence = confidenceOf(ja.Confidence, ja.Probabilities, ja.Choice)
		case Score:
			if ja.Score != nil {
				a.Score = *ja.Score
			}
			a.Confidence = confidenceOf(ja.Confidence, ja.Probabilities, fmt.Sprint(a.Score))
		case Probability:
			if ja.Noul == nil {
				return nil, fmt.Errorf("jev: %s: missing probability", q.ID)
			}
			a.Probability = *ja.Noul
			a.Confidence = max(a.Probability, 1-a.Probability)
			a.Probabilities = map[string]float64{"true": a.Probability, "false": 1 - a.Probability}
		}
		res.Answers[q.ID] = a
	}
	return res, nil
}

func confidenceOf(c *float64, probs map[string]float64, key string) float64 {
	if c != nil {
		return *c
	}
	return probs[key]
}

// post sends with retries (see Retry). Response bodies never reach error
// messages: a reflecting endpoint could echo the key.
func (j *Jev) post(ctx context.Context, body []byte) ([]byte, error) {
	if err := j.Limit.acquire(ctx); err != nil {
		return nil, err
	}
	defer j.Limit.release()
	url := strings.TrimRight(j.BaseURL, "/") + j.path
	var data []byte
	err := j.Retry.do(ctx, "jev", func() (int, string, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return -1, "", err
		}
		req.Header.Set("Authorization", "Bearer "+j.APIKey)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		resp, err := j.HTTP.Do(req)
		if err != nil {
			return 0, "", err
		}
		b, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close() // fully read
		if resp.StatusCode != http.StatusOK {
			return resp.StatusCode, "", fmt.Errorf("status %d", resp.StatusCode)
		}
		if readErr != nil {
			return 0, "reading response", readErr
		}
		data = b
		return resp.StatusCode, "", nil
	})
	return data, err
}
