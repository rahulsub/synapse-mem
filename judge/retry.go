package judge

import (
	"context"
	"fmt"
	"math/rand/v2"
	"time"
)

// Retry is how a judge retries calls that weren't processed (408, 409, 429,
// 5xx, network errors). Judges often share seats with other agents, so the
// defaults back off exponentially (1s, 2s, 4s, 8s, with jitter) and give up
// after four attempts rather than hammering a busy endpoint.
type Retry struct {
	Attempts int
	Base     time.Duration
	Max      time.Duration
}

// DefaultRetry is used when a judge's Retry is zero.
var DefaultRetry = Retry{Attempts: 4, Base: time.Second, Max: 8 * time.Second}

func (r Retry) orDefault() Retry {
	if r.Attempts <= 0 {
		return DefaultRetry
	}
	if r.Base <= 0 {
		r.Base = DefaultRetry.Base
	}
	if r.Max <= 0 {
		r.Max = DefaultRetry.Max
	}
	return r
}

// HTTPError is a judge call that failed, with the last HTTP status (0 when
// the request never got a response). It never carries the response body: a
// reflecting endpoint could echo credentials.
type HTTPError struct {
	Judge    string
	Status   int
	Attempts int
	Detail   string
}

func (e *HTTPError) Error() string {
	s := fmt.Sprintf("%s: HTTP %d", e.Judge, e.Status)
	if e.Status == 0 {
		s = e.Judge + ": request failed"
	}
	if e.Detail != "" {
		s += " (" + e.Detail + ")"
	}
	if e.Attempts > 1 {
		s += fmt.Sprintf(" after %d attempts", e.Attempts)
	}
	return s
}

func retryable(status int) bool {
	return status == 0 || status == 408 || status == 409 || status == 429 || status >= 500
}

// do calls fn until it succeeds, fails with a status that isn't worth
// retrying, or runs out of attempts. fn returns the HTTP status (0 if there
// was no response) and an error.
func (r Retry) do(ctx context.Context, judge string, fn func() (int, string, error)) error {
	r = r.orDefault()
	delay := r.Base
	for attempt := 1; ; attempt++ {
		status, detail, err := fn()
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !retryable(status) || attempt >= r.Attempts {
			return &HTTPError{Judge: judge, Status: status, Attempts: attempt, Detail: detail}
		}
		// ±25% jitter so agents sharing a seat don't retry in step.
		wait := delay + time.Duration((rand.Float64()-0.5)*0.5*float64(delay)) //nolint:gosec // jitter, not security
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return ctx.Err()
		}
		delay = min(delay*2, r.Max)
	}
}

// Limiter caps concurrent calls to one judge within a process.
type Limiter chan struct{}

// NewLimiter allows n calls at once (at least one).
func NewLimiter(n int) Limiter { return make(Limiter, max(n, 1)) }

func (l Limiter) acquire(ctx context.Context) error {
	if l == nil {
		return nil
	}
	select {
	case l <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l Limiter) release() {
	if l != nil {
		<-l
	}
}
