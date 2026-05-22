package httpclient

import (
	"context"
	"errors"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// RetryDecider decides whether a request should be retried and for how long.
// Returning wait=0 means the transport should use exponential backoff.
type RetryDecider func(req *http.Request, resp *http.Response, err error, now time.Time) (retry bool, wait time.Duration)

// RateLimitStateExtractor extracts provider-specific rate-limit state from a response.
// If ok is false, the transport keeps the previous values.
type RateLimitStateExtractor func(resp *http.Response) (remaining int64, resetAt time.Time, ok bool)

// RetryTransport wraps an http.RoundTripper with retry and shared pause logic.
// It is safe for concurrent use.
type RetryTransport struct {
	// Base is the underlying RoundTripper. If nil, http.DefaultTransport is used.
	Base http.RoundTripper

	// MaxRetries is the maximum number of retries per request.
	MaxRetries int

	// MaxBackoff caps exponential backoff sleep for transient retries.
	MaxBackoff time.Duration

	// Sleep is overridable for tests.
	Sleep func(ctx context.Context, d time.Duration) error

	// Now is overridable for tests.
	Now func() time.Time

	// Jitter is optional extra delay added to exponential backoff sleeps.
	Jitter func() time.Duration

	// Decider customizes retry policy.
	Decider RetryDecider

	// StateExtractor optionally records provider-specific rate-limit state.
	StateExtractor RateLimitStateExtractor

	mu       sync.Mutex
	resumeAt time.Time

	rateLimitResetUnix atomic.Int64
	rateLimitRemaining atomic.Int64
}

// NewRetryTransport constructs a RetryTransport with sensible defaults.
func NewRetryTransport(base http.RoundTripper) *RetryTransport {
	return &RetryTransport{
		Base:       base,
		MaxRetries: 5,
		MaxBackoff: 30 * time.Second,
		Decider:    DefaultRetryDecider,
	}
}

func (t *RetryTransport) base() http.RoundTripper {
	if t.Base != nil {
		return t.Base
	}
	return http.DefaultTransport
}

func (t *RetryTransport) sleep(ctx context.Context, d time.Duration) error {
	if t.Sleep != nil {
		return t.Sleep(ctx, d)
	}
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (t *RetryTransport) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

func (t *RetryTransport) jitter() time.Duration {
	if t.Jitter != nil {
		return t.Jitter()
	}
	return time.Duration(rand.Int63n(int64(5 * time.Second)))
}

func (t *RetryTransport) decider() RetryDecider {
	if t.Decider != nil {
		return t.Decider
	}
	return DefaultRetryDecider
}

// RoundTrip implements http.RoundTripper.
func (t *RetryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()

	if err := t.waitForResume(ctx); err != nil {
		return nil, err
	}

	var lastResp *http.Response
	var lastErr error

	for attempt := 0; attempt <= t.MaxRetries; attempt++ {
		resp, err := t.base().RoundTrip(req)
		lastResp, lastErr = resp, err
		t.recordRateLimitHeaders(resp)

		retry, wait := t.decider()(req, resp, err, t.now())
		if !retry {
			return resp, err
		}

		// Network errors only retry idempotent requests.
		if err != nil && !isIdempotent(req.Method) {
			return resp, err
		}
		if attempt == t.MaxRetries {
			return resp, err
		}

		// Ensure connections can be reused before retrying.
		if resp != nil {
			drainAndClose(resp)
		}

		// Rewind the request body for the next attempt.
		if req.GetBody != nil {
			var bodyErr error
			req.Body, bodyErr = req.GetBody()
			if bodyErr != nil {
				return nil, bodyErr
			}
		} else if req.Body != nil {
			return lastResp, lastErr
		}

		// Explicit waits (e.g. Retry-After/rate-limit reset) bypass jitter/backoff.
		if wait <= 0 {
			wait = t.backoff(attempt)
		} else {
			t.recordPause(wait)
		}

		if sleepErr := t.sleep(ctx, wait); sleepErr != nil {
			return nil, sleepErr
		}
	}

	return lastResp, lastErr
}

// DefaultRetryDecider is generic: Retry-After on 429/503, transient 5xx, and
// retryable network errors.
func DefaultRetryDecider(_ *http.Request, resp *http.Response, err error, now time.Time) (bool, time.Duration) {
	if err != nil {
		return shouldRetryErr(err), 0
	}
	if resp == nil {
		return false, 0
	}
	if resp.StatusCode < 400 {
		return false, 0
	}
	if wait, ok := retryAfterForRetryableStatus(resp, now); ok {
		return true, wait
	}
	if resp.StatusCode >= 500 && resp.StatusCode < 600 {
		return true, 0
	}
	return false, 0
}

// PauseFor records a rate-limit pause that all callers through this transport
// will respect.
func (t *RetryTransport) PauseFor(pause time.Duration) {
	t.recordPause(pause)
}

// RateLimitReset returns the most recently observed provider reset time.
func (t *RetryTransport) RateLimitReset() time.Time {
	ts := t.rateLimitResetUnix.Load()
	if ts == 0 {
		return time.Time{}
	}
	return time.Unix(ts, 0)
}

// RateLimitRemaining returns the most recently observed provider remaining value.
func (t *RetryTransport) RateLimitRemaining() int64 {
	return t.rateLimitRemaining.Load()
}

func (t *RetryTransport) recordRateLimitHeaders(resp *http.Response) {
	if resp == nil {
		return
	}
	if t.StateExtractor == nil {
		return
	}
	remaining, resetAt, ok := t.StateExtractor(resp)
	if !ok {
		return
	}
	t.rateLimitRemaining.Store(remaining)
	if !resetAt.IsZero() {
		t.rateLimitResetUnix.Store(resetAt.Unix())
	}
}

func (t *RetryTransport) waitForResume(ctx context.Context) error {
	t.mu.Lock()
	resume := t.resumeAt
	t.mu.Unlock()

	now := t.now()
	if !resume.After(now) {
		return nil
	}
	return t.sleep(ctx, resume.Sub(now))
}

func (t *RetryTransport) recordPause(d time.Duration) {
	if d <= 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	resume := t.now().Add(d)
	if resume.After(t.resumeAt) {
		t.resumeAt = resume
	}
}

func (t *RetryTransport) backoff(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	d := time.Second << attempt
	if d <= 0 || d > t.MaxBackoff {
		d = t.MaxBackoff
	}
	return d + t.jitter()
}

// retryAfterForRetryableStatus handles Retry-After for generally retryable statuses.
func retryAfterForRetryableStatus(resp *http.Response, now time.Time) (time.Duration, bool) {
	if resp == nil {
		return 0, false
	}
	if resp.StatusCode >= 400 && resp.StatusCode < 600 {
		if d := retryAfterDuration(resp, now); d > 0 {
			return d, true
		}
	}
	switch resp.StatusCode {
	case http.StatusTooManyRequests:
		return 60 * time.Second, true
	case http.StatusServiceUnavailable:
		return 60 * time.Second, true
	}
	return 0, false
}

func retryAfterDuration(resp *http.Response, now time.Time) time.Duration {
	v := resp.Header.Get("Retry-After")
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	if when, err := http.ParseTime(v); err == nil {
		if d := when.Sub(now); d > 0 {
			return d
		}
	}
	return 0
}

func isIdempotent(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	}
	return false
}

func shouldRetryErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	return true
}

func drainAndClose(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}
