package httpclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
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

func TestRetryTransport(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		status, failures, retries int
		retryAfter                string
		wantStatus, wantCalls     int
		wantSleeps                []time.Duration
	}{
		{
			name:   "429 default delay",
			status: http.StatusTooManyRequests, failures: 1, retries: 5, retryAfter: "",
			wantStatus: http.StatusOK, wantCalls: 2,
			wantSleeps: []time.Duration{60 * time.Second},
		},
		{
			name:   "secondary rate limit",
			status: http.StatusForbidden, failures: 1, retries: 5, retryAfter: "3",
			wantStatus: http.StatusOK, wantCalls: 2,
			wantSleeps: []time.Duration{3 * time.Second},
		},
		{
			name:   "429 explicit delay",
			status: http.StatusTooManyRequests, failures: 1, retries: 5, retryAfter: "2",
			wantStatus: http.StatusOK, wantCalls: 2,
			wantSleeps: []time.Duration{2 * time.Second},
		},
		{
			name:   "server backoff",
			status: http.StatusInternalServerError, failures: 2, retries: 5, retryAfter: "",
			wantStatus: http.StatusOK, wantCalls: 3,
			wantSleeps: []time.Duration{time.Second, 2 * time.Second},
		},
		{
			name:   "client error",
			status: http.StatusBadRequest, failures: 1, retries: 5, retryAfter: "",
			wantStatus: http.StatusBadRequest, wantCalls: 1,
			wantSleeps: nil,
		},
		{
			name:   "retries exhausted",
			status: http.StatusInternalServerError, failures: 3, retries: 2, retryAfter: "",
			wantStatus: http.StatusInternalServerError, wantCalls: 3,
			wantSleeps: []time.Duration{time.Second, 2 * time.Second},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if int(calls.Add(1)) <= tc.failures {
					if tc.retryAfter != "" {
						w.Header().Set("Retry-After", tc.retryAfter)
					}
					w.WriteHeader(tc.status)
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			transport, sleeps := newTestTransport(http.DefaultTransport)
			transport.MaxRetries = tc.retries
			client := &http.Client{Transport: transport}
			response, err := client.Get(server.URL)
			require.NoError(t, err)
			defer response.Body.Close()
			require.Equal(t, tc.wantStatus, response.StatusCode)
			require.EqualValues(t, tc.wantCalls, calls.Load())
			require.Equal(t, tc.wantSleeps, sleeps.durations)
		})
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
