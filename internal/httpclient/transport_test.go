package httpclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// noJitter eliminates randomness in tests; tests assert on exact sleep totals.
func noJitter() time.Duration { return 0 }

// recordingSleeper records every sleep duration without actually sleeping.
type recordingSleeper struct {
	durations []time.Duration
}

func (r *recordingSleeper) sleep(_ context.Context, d time.Duration) error {
	r.durations = append(r.durations, d)
	return nil
}

func newTestTransport(base http.RoundTripper) (*RetryTransport, *recordingSleeper) {
	rs := &recordingSleeper{}
	rt := &RetryTransport{
		Base:       base,
		MaxRetries: 5,
		MaxBackoff: 30 * time.Second,
		Sleep:      rs.sleep,
		Jitter:     noJitter,
		Decider:    DefaultRetryDecider,
	}
	return rt, rs
}

func TestRoundTrip_429DefaultRetry(t *testing.T) {
	var calls atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rt, rs := newTestTransport(http.DefaultTransport)
	client := &http.Client{Transport: rt}

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("got status %d, want 200", resp.StatusCode)
	}
	if calls.Load() != 2 {
		t.Errorf("expected 2 calls, got %d", calls.Load())
	}
	if len(rs.durations) != 1 {
		t.Fatalf("expected 1 sleep, got %d", len(rs.durations))
	}
	if rs.durations[0] != 60*time.Second {
		t.Errorf("429 default sleep = %v, want 60s", rs.durations[0])
	}
}

func TestRoundTrip_SecondaryRateLimit(t *testing.T) {
	var calls atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "3")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rt, rs := newTestTransport(http.DefaultTransport)
	client := &http.Client{Transport: rt}

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("got status %d, want 200", resp.StatusCode)
	}
	if len(rs.durations) != 1 || rs.durations[0] != 3*time.Second {
		t.Errorf("expected one 3s sleep, got %v", rs.durations)
	}
}

func TestRoundTrip_429(t *testing.T) {
	var calls atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "2")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rt, rs := newTestTransport(http.DefaultTransport)
	client := &http.Client{Transport: rt}

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("got status %d, want 200", resp.StatusCode)
	}
	if len(rs.durations) != 1 || rs.durations[0] != 2*time.Second {
		t.Errorf("expected one 2s sleep, got %v", rs.durations)
	}
}

func TestRoundTrip_5xxBackoff(t *testing.T) {
	var calls atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) <= 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rt, rs := newTestTransport(http.DefaultTransport)
	client := &http.Client{Transport: rt}

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("got status %d, want 200", resp.StatusCode)
	}
	// Two 5xx responses -> two backoff sleeps: 1s, 2s.
	if len(rs.durations) != 2 {
		t.Fatalf("expected 2 sleeps, got %v", rs.durations)
	}
	if rs.durations[0] != time.Second {
		t.Errorf("first backoff = %v, want 1s", rs.durations[0])
	}
	if rs.durations[1] != 2*time.Second {
		t.Errorf("second backoff = %v, want 2s", rs.durations[1])
	}
}

func TestRoundTrip_4xxNoRetry(t *testing.T) {
	var calls atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	rt, rs := newTestTransport(http.DefaultTransport)
	client := &http.Client{Transport: rt}

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("got status %d, want 400", resp.StatusCode)
	}
	if calls.Load() != 1 {
		t.Errorf("expected 1 call, got %d", calls.Load())
	}
	if len(rs.durations) != 0 {
		t.Errorf("expected no sleeps, got %v", rs.durations)
	}
}

func TestRoundTrip_MaxRetriesExhausted(t *testing.T) {
	var calls atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	rt, _ := newTestTransport(http.DefaultTransport)
	rt.MaxRetries = 2
	client := &http.Client{Transport: rt}

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("got status %d, want 500", resp.StatusCode)
	}
	// MaxRetries=2 means up to 3 total attempts (1 + 2 retries).
	if got := calls.Load(); got != 3 {
		t.Errorf("expected 3 calls, got %d", got)
	}
}

func TestRoundTrip_ContextCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	rt := &RetryTransport{
		Base:       http.DefaultTransport,
		MaxRetries: 5,
		MaxBackoff: 30 * time.Second,
		Sleep: func(ctx context.Context, _ time.Duration) error {
			return ctx.Err()
		},
		Jitter:  noJitter,
		Decider: DefaultRetryDecider,
	}
	client := &http.Client{Transport: rt}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	_, err := client.Do(req)
	if err == nil {
		t.Fatal("expected error from cancelled context, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestRetryAfterForRetryableStatus(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	tests := []struct {
		name   string
		status int
		hdr    http.Header
		want   time.Duration
		ok     bool
	}{
		{
			name:   "403 with retry-after",
			status: http.StatusForbidden,
			hdr:    http.Header{"Retry-After": []string{"7"}},
			want:   7 * time.Second,
			ok:     true,
		},
		{
			name:   "429 with retry-after",
			status: http.StatusTooManyRequests,
			hdr:    http.Header{"Retry-After": []string{"7"}},
			want:   7 * time.Second,
			ok:     true,
		},
		{
			name:   "429 without retry-after defaults to 60s",
			status: http.StatusTooManyRequests,
			want:   60 * time.Second,
			ok:     true,
		},
		{
			name:   "503 retry-after",
			status: http.StatusServiceUnavailable,
			hdr:    http.Header{"Retry-After": []string{"5"}},
			want:   5 * time.Second,
			ok:     true,
		},
		{
			name:   "403 forbidden is not generic retry-after status",
			status: http.StatusForbidden,
			ok:     false,
		},
		{
			name:   "200 ok is not a rate limit",
			status: http.StatusOK,
			ok:     false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := &http.Response{StatusCode: tc.status, Header: tc.hdr}
			if resp.Header == nil {
				resp.Header = http.Header{}
			}
			got, ok := retryAfterForRetryableStatus(resp, now)
			if ok != tc.ok {
				t.Fatalf("ok=%v, want %v", ok, tc.ok)
			}
			if !ok {
				return
			}
			// Allow +-1s slop for the primary-reset case where time.Until is involved.
			if got < tc.want-time.Second || got > tc.want+time.Second {
				t.Errorf("duration = %v, want ~%v", got, tc.want)
			}
		})
	}
}
