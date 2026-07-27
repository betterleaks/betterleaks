package exprruntime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ValidationRequestLimits controls outbound validation requests. Zero values
// disable the corresponding limit.
type ValidationRequestLimits struct {
	// MaxRequestsPerTarget is the maximum number of requests admitted to each
	// target origin over the lifetime of the Runtime.
	MaxRequestsPerTarget int

	// RequestsPerSecond is the aggregate request rate across all validation
	// targets and rules.
	RequestsPerSecond float64

	// RequestsPerSecondByRule contains exact rule-ID request rates. A rule rate
	// composes with, rather than replaces, RequestsPerSecond.
	RequestsPerSecondByRule map[string]float64
}

// ValidationRequestLimitHit describes a validation request rejected before it
// reached the provider.
type ValidationRequestLimitHit struct {
	RuleID       string
	Target       string
	MaxRequests  int
	RequestsSent int
}

// ValidationRequestLimitError is returned by the validation HTTP transport
// when a target has exhausted its request budget.
type ValidationRequestLimitError struct {
	Hit ValidationRequestLimitHit
}

func (e *ValidationRequestLimitError) Error() string {
	return fmt.Sprintf(
		"validation request limit reached for %s (%d requests sent, maximum %d)",
		e.Hit.Target,
		e.Hit.RequestsSent,
		e.Hit.MaxRequests,
	)
}

type validationRequestContextKey struct{}

type validationRequestContext struct {
	ruleID string
	state  *evalState
}

type validationTimeoutBudgetContextKey struct{}

type validationRequestLimiter struct {
	mu sync.Mutex

	maxRequestsPerTarget int
	requestsByTarget     map[string]int

	globalInterval time.Duration
	globalNext     time.Time
	ruleIntervals  map[string]time.Duration
	ruleNext       map[string]time.Time
}

func newValidationRequestLimiter(cfg ValidationRequestLimits) (*validationRequestLimiter, error) {
	if cfg.MaxRequestsPerTarget < 0 {
		return nil, errors.New("validation maximum requests must be non-negative")
	}

	globalInterval, err := validationRequestInterval(cfg.RequestsPerSecond)
	if err != nil {
		return nil, fmt.Errorf("validation requests per second: %w", err)
	}

	ruleIntervals := make(map[string]time.Duration, len(cfg.RequestsPerSecondByRule))
	for rawRuleID, rps := range cfg.RequestsPerSecondByRule {
		ruleID := strings.TrimSpace(rawRuleID)
		if ruleID == "" {
			return nil, errors.New("validation rule request rate has an empty rule ID")
		}
		interval, intervalErr := validationRequestInterval(rps)
		if intervalErr != nil {
			return nil, fmt.Errorf("validation requests per second for rule %q: %w", ruleID, intervalErr)
		}
		if interval == 0 {
			return nil, fmt.Errorf("validation requests per second for rule %q must be greater than zero", ruleID)
		}
		ruleIntervals[ruleID] = interval
	}

	if cfg.MaxRequestsPerTarget == 0 && globalInterval == 0 && len(ruleIntervals) == 0 {
		return nil, nil
	}

	return &validationRequestLimiter{
		maxRequestsPerTarget: cfg.MaxRequestsPerTarget,
		requestsByTarget:     make(map[string]int),
		globalInterval:       globalInterval,
		ruleIntervals:        ruleIntervals,
		ruleNext:             make(map[string]time.Time),
	}, nil
}

func validationRequestInterval(rps float64) (time.Duration, error) {
	if math.IsNaN(rps) || math.IsInf(rps, 0) || rps < 0 {
		return 0, errors.New("must be a finite non-negative number")
	}
	if rps == 0 {
		return 0, nil
	}

	seconds := 1 / rps
	if seconds > float64(math.MaxInt64)/float64(time.Second) {
		return 0, errors.New("is too small to represent")
	}
	interval := time.Duration(seconds * float64(time.Second))
	if interval <= 0 {
		return 0, errors.New("is too large to represent")
	}
	return interval, nil
}

// wait admits a request only when both the global and exact-rule rate limits
// have a current slot. Future slots are not reserved: a slow rule therefore
// cannot block unrelated rules from using otherwise available global capacity.
func (l *validationRequestLimiter) wait(ctx context.Context, ruleID string) error {
	if l == nil || (l.globalInterval == 0 && l.ruleIntervals[ruleID] == 0) {
		return nil
	}

	ruleInterval := l.ruleIntervals[ruleID]
	for {
		now := time.Now()
		l.mu.Lock()
		sendAt := now
		if l.globalInterval > 0 && l.globalNext.After(sendAt) {
			sendAt = l.globalNext
		}
		if ruleInterval > 0 && l.ruleNext[ruleID].After(sendAt) {
			sendAt = l.ruleNext[ruleID]
		}
		if !sendAt.After(now) {
			if l.globalInterval > 0 {
				l.globalNext = now.Add(l.globalInterval)
			}
			if ruleInterval > 0 {
				l.ruleNext[ruleID] = now.Add(ruleInterval)
			}
			l.mu.Unlock()
			return nil
		}
		l.mu.Unlock()

		timer := time.NewTimer(time.Until(sendAt))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (l *validationRequestLimiter) admit(ruleID, target string) *ValidationRequestLimitHit {
	if l == nil || l.maxRequestsPerTarget == 0 {
		return nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if hit := l.limitHitLocked(ruleID, target); hit != nil {
		return hit
	}
	l.requestsByTarget[target]++
	return nil
}

func (l *validationRequestLimiter) limitHit(ruleID, target string) *ValidationRequestLimitHit {
	if l == nil || l.maxRequestsPerTarget == 0 {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.limitHitLocked(ruleID, target)
}

func (l *validationRequestLimiter) limitHitLocked(ruleID, target string) *ValidationRequestLimitHit {
	sent := l.requestsByTarget[target]
	if sent >= l.maxRequestsPerTarget {
		return &ValidationRequestLimitHit{
			RuleID:       ruleID,
			Target:       target,
			MaxRequests:  l.maxRequestsPerTarget,
			RequestsSent: sent,
		}
	}
	return nil
}

type validationLimitTransport struct {
	base           http.RoundTripper
	limiter        *validationRequestLimiter
	requestTimeout time.Duration
}

func (t *validationLimitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	if t.limiter == nil {
		return base.RoundTrip(req)
	}

	requestContext, _ := req.Context().Value(validationRequestContextKey{}).(*validationRequestContext)
	ruleID := ""
	if requestContext != nil {
		ruleID = requestContext.ruleID
	}

	target := validationRequestTarget(req.URL)
	if hit := t.limiter.limitHit(ruleID, target); hit != nil {
		if requestContext != nil && requestContext.state != nil {
			requestContext.state.recordValidationLimitHit(*hit)
		}
		return nil, &ValidationRequestLimitError{Hit: *hit}
	}

	if err := t.limiter.wait(req.Context(), ruleID); err != nil {
		return nil, err
	}
	if err := req.Context().Err(); err != nil {
		return nil, err
	}

	timeoutBudget := validationTimeoutBudgetForRequest(req, t.requestTimeout)
	if timeoutBudget != nil && !timeoutBudget.hasRemaining() {
		return nil, context.DeadlineExceeded
	}

	if hit := t.limiter.admit(ruleID, target); hit != nil {
		if requestContext != nil && requestContext.state != nil {
			requestContext.state.recordValidationLimitHit(*hit)
		}
		return nil, &ValidationRequestLimitError{Hit: *hit}
	}

	providerReq := req
	var finishProviderRequest func()
	if timeoutBudget != nil {
		providerCtx, finish, err := timeoutBudget.start(req.Context())
		if err != nil {
			return nil, err
		}
		providerCtx = context.WithValue(providerCtx, validationTimeoutBudgetContextKey{}, timeoutBudget)
		providerReq = req.Clone(providerCtx)
		finishProviderRequest = finish
	}

	resp, err := base.RoundTrip(providerReq)
	if err != nil {
		if finishProviderRequest != nil {
			finishProviderRequest()
		}
		return nil, err
	}
	if finishProviderRequest != nil {
		if resp.Body == nil {
			finishProviderRequest()
		} else {
			resp.Body = &validationTimeoutBody{
				ReadCloser: resp.Body,
				finish:     finishProviderRequest,
			}
		}
	}
	// Preserve the shared timeout budget for a redirect request even when a
	// custom RoundTripper omits or replaces Response.Request.
	resp.Request = providerReq
	return resp, nil
}

// validationTimeoutBudget tracks provider-active time across every request in
// one redirect chain. Rate-limit waits happen before start and do not consume
// the budget.
type validationTimeoutBudget struct {
	mu        sync.Mutex
	remaining time.Duration
}

// validationTimeoutBudgetForRequest starts a budget for an initial request and
// recovers it from the previous response for redirects. The budget value
// survives cancellation of the prior hop's request context.
func validationTimeoutBudgetForRequest(req *http.Request, timeout time.Duration) *validationTimeoutBudget {
	if timeout <= 0 {
		return nil
	}
	if req != nil && req.Response != nil && req.Response.Request != nil {
		if budget, ok := req.Response.Request.Context().Value(validationTimeoutBudgetContextKey{}).(*validationTimeoutBudget); ok {
			return budget
		}
	}
	return &validationTimeoutBudget{remaining: timeout}
}

func (b *validationTimeoutBudget) hasRemaining() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.remaining > 0
}

func (b *validationTimeoutBudget) start(parent context.Context) (context.Context, func(), error) {
	b.mu.Lock()
	remaining := b.remaining
	b.mu.Unlock()
	if remaining <= 0 {
		return nil, nil, context.DeadlineExceeded
	}

	started := time.Now()
	ctx, cancel := context.WithTimeout(parent, remaining)
	var once sync.Once
	finish := func() {
		once.Do(func() {
			cancel()
			elapsed := time.Since(started)
			b.mu.Lock()
			b.remaining = max(0, b.remaining-elapsed)
			b.mu.Unlock()
		})
	}
	return ctx, finish, nil
}

// validationTimeoutBody keeps the provider request context alive until the
// response body is consumed or closed and then charges that active time to the
// redirect chain's shared timeout budget.
type validationTimeoutBody struct {
	io.ReadCloser
	finish func()
	once   sync.Once
}

func (b *validationTimeoutBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil {
		b.once.Do(b.finish)
	}
	return n, err
}

func (b *validationTimeoutBody) Close() error {
	b.once.Do(b.finish)
	return b.ReadCloser.Close()
}

func validationRequestTarget(u *url.URL) string {
	if u == nil {
		return "unknown"
	}
	scheme := strings.ToLower(u.Scheme)
	hostname := strings.ToLower(u.Hostname())
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	host := hostname
	if port != "" {
		host = net.JoinHostPort(hostname, port)
	} else if strings.Contains(hostname, ":") {
		host = "[" + hostname + "]"
	}
	if host == "" {
		host = strings.ToLower(u.Host)
	}
	if scheme == "" {
		return host
	}
	return scheme + "://" + host
}

func wrapValidationLimitClient(client *http.Client, limiter *validationRequestLimiter) *http.Client {
	if client == nil {
		client = DefaultHTTPClient()
	}
	clone := *client
	base := clone.Transport
	requestTimeout := clone.Timeout
	if current, ok := base.(*validationLimitTransport); ok {
		base = current.base
		if requestTimeout == 0 {
			requestTimeout = current.requestTimeout
		}
	}
	clone.Transport = base
	if limiter != nil {
		// http.Client.Timeout starts before RoundTrip, so leaving it here would
		// count rate-limit queue time against the provider request. The wrapper
		// starts the same timeout immediately before the underlying RoundTrip.
		clone.Timeout = 0
		clone.Transport = &validationLimitTransport{
			base:           base,
			limiter:        limiter,
			requestTimeout: requestTimeout,
		}
	} else {
		clone.Timeout = requestTimeout
	}
	return &clone
}
