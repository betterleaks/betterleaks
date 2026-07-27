package exprruntime

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

type validationRecordingTransport struct {
	mu      sync.Mutex
	targets []string
	times   []time.Time
}

func (t *validationRecordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.targets = append(t.targets, validationRequestTarget(req.URL))
	t.times = append(t.times, time.Now())
	t.mu.Unlock()
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
		Request:    req,
	}, nil
}

func (t *validationRecordingTransport) snapshot() ([]string, []time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.targets...), append([]time.Time(nil), t.times...)
}

func TestValidationMaxRequestsSharedByTargetAcrossRules(t *testing.T) {
	recorder := &validationRecordingTransport{}
	rt, err := New(&http.Client{Transport: recorder})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := rt.SetValidationRequestLimits(ValidationRequestLimits{MaxRequestsPerTarget: 2}); err != nil {
		t.Fatalf("SetValidationRequestLimits: %v", err)
	}

	firstTarget, err := rt.CompileValidation(`http.get("https://api.example.test/v1/check", {}).status`)
	if err != nil {
		t.Fatalf("compile first target: %v", err)
	}
	otherTarget, err := rt.CompileValidation(`http.get("https://other.example.test/check", {}).status`)
	if err != nil {
		t.Fatalf("compile other target: %v", err)
	}

	for _, ruleID := range []string{"rule-a", "rule-b"} {
		result, evalErr := rt.EvalValidation(
			context.Background(),
			firstTarget,
			map[string]string{"rule_id": ruleID},
			nil,
			nil,
			EvalOptions{},
		)
		if evalErr != nil {
			t.Fatalf("admitted evaluation for %s: %v", ruleID, evalErr)
		}
		if result.RequestLimitHit != nil {
			t.Fatalf("admitted evaluation for %s reported limit: %#v", ruleID, result.RequestLimitHit)
		}
	}

	blocked, evalErr := rt.EvalValidation(
		context.Background(),
		firstTarget,
		map[string]string{"rule_id": "rule-c"},
		nil,
		nil,
		EvalOptions{},
	)
	if evalErr == nil {
		t.Fatal("blocked evaluation returned no expression error")
	}
	if blocked.RequestLimitHit == nil {
		t.Fatal("blocked evaluation did not report request limit")
	}
	if got, want := blocked.RequestLimitHit.Target, "https://api.example.test"; got != want {
		t.Fatalf("target = %q, want %q", got, want)
	}
	if got, want := blocked.RequestLimitHit.RequestsSent, 2; got != want {
		t.Fatalf("requests sent = %d, want %d", got, want)
	}
	if got, want := blocked.RequestLimitHit.RuleID, "rule-c"; got != want {
		t.Fatalf("rule ID = %q, want %q", got, want)
	}

	if _, evalErr := rt.EvalValidation(
		context.Background(),
		otherTarget,
		map[string]string{"rule_id": "rule-c"},
		nil,
		nil,
		EvalOptions{},
	); evalErr != nil {
		t.Fatalf("different target should have its own budget: %v", evalErr)
	}

	targets, _ := recorder.snapshot()
	if got, want := len(targets), 3; got != want {
		t.Fatalf("provider requests = %d, want %d", got, want)
	}
}

func TestValidationLimitsCoverTypedCloudBindings(t *testing.T) {
	recorder := &validationRecordingTransport{}
	rt, err := New(&http.Client{Transport: recorder})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rt.STSEndpoint = "https://api.example.test/sts"
	if err := rt.SetValidationRequestLimits(ValidationRequestLimits{MaxRequestsPerTarget: 1}); err != nil {
		t.Fatalf("SetValidationRequestLimits: %v", err)
	}

	generic, err := rt.CompileValidation(`http.get("https://api.example.test/check", {}).status`)
	if err != nil {
		t.Fatalf("compile generic: %v", err)
	}
	if _, err := rt.EvalValidation(
		context.Background(),
		generic,
		map[string]string{"rule_id": "generic-rule"},
		nil,
		nil,
		EvalOptions{},
	); err != nil {
		t.Fatalf("generic evaluation: %v", err)
	}

	awsProgram, err := rt.CompileValidation(
		`aws.validate("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY").status`,
	)
	if err != nil {
		t.Fatalf("compile AWS: %v", err)
	}
	blocked, _ := rt.EvalValidation(
		context.Background(),
		awsProgram,
		map[string]string{"rule_id": "aws-secret-access-key"},
		nil,
		nil,
		EvalOptions{},
	)
	if blocked.RequestLimitHit == nil {
		t.Fatal("typed AWS validation did not report shared request limit")
	}
	if got, want := blocked.RequestLimitHit.Target, "https://api.example.test"; got != want {
		t.Fatalf("target = %q, want %q", got, want)
	}
	targets, _ := recorder.snapshot()
	if got, want := len(targets), 1; got != want {
		t.Fatalf("provider requests = %d, want %d", got, want)
	}
}

func TestValidationMaxRequestsDoesNotWaitForRPSAfterTargetIsExhausted(t *testing.T) {
	recorder := &validationRecordingTransport{}
	rt, err := New(&http.Client{Transport: recorder})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := rt.SetValidationRequestLimits(ValidationRequestLimits{
		MaxRequestsPerTarget: 1,
		RequestsPerSecond:    1,
	}); err != nil {
		t.Fatalf("SetValidationRequestLimits: %v", err)
	}
	prg, err := rt.CompileValidation(`http.get("https://api.example.test/check", {}).status`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	if _, err := rt.EvalValidation(
		context.Background(),
		prg,
		map[string]string{"rule_id": "rule"},
		nil,
		nil,
		EvalOptions{},
	); err != nil {
		t.Fatalf("first evaluation: %v", err)
	}

	start := time.Now()
	blocked, _ := rt.EvalValidation(
		context.Background(),
		prg,
		map[string]string{"rule_id": "rule"},
		nil,
		nil,
		EvalOptions{},
	)
	if blocked.RequestLimitHit == nil {
		t.Fatal("second evaluation did not report request limit")
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("exhausted target waited %s for RPS limit", elapsed)
	}
}

func TestValidationGlobalRPSStrictlySpacesRequests(t *testing.T) {
	recorder := &validationRecordingTransport{}
	rt, err := New(&http.Client{Transport: recorder})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := rt.SetValidationRequestLimits(ValidationRequestLimits{RequestsPerSecond: 50}); err != nil {
		t.Fatalf("SetValidationRequestLimits: %v", err)
	}
	prg, err := rt.CompileValidation(`http.get("https://api.example.test/check", {}).status`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	runConcurrentValidations(t, rt, prg, "rule", 3)
	_, times := recorder.snapshot()
	assertMinimumRequestSpacing(t, times, 15*time.Millisecond)
}

func TestValidationRuleRPSComposesWithGlobalRPS(t *testing.T) {
	for _, test := range []struct {
		name      string
		globalRPS float64
		ruleRPS   float64
	}{
		{name: "rule is stricter", globalRPS: 100, ruleRPS: 20},
		{name: "global is stricter", globalRPS: 20, ruleRPS: 100},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorder := &validationRecordingTransport{}
			rt, err := New(&http.Client{Transport: recorder})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if err := rt.SetValidationRequestLimits(ValidationRequestLimits{
				RequestsPerSecond:       test.globalRPS,
				RequestsPerSecondByRule: map[string]float64{"limited-rule": test.ruleRPS},
			}); err != nil {
				t.Fatalf("SetValidationRequestLimits: %v", err)
			}
			prg, err := rt.CompileValidation(`http.get("https://api.example.test/check", {}).status`)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}

			runConcurrentValidations(t, rt, prg, "limited-rule", 3)
			_, times := recorder.snapshot()
			assertMinimumRequestSpacing(t, times, 40*time.Millisecond)
		})
	}
}

func TestValidationRPSWaitHonorsCancellationAndDoesNotCountRequest(t *testing.T) {
	recorder := &validationRecordingTransport{}
	rt, err := New(&http.Client{Transport: recorder})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := rt.SetValidationRequestLimits(ValidationRequestLimits{RequestsPerSecond: 1}); err != nil {
		t.Fatalf("SetValidationRequestLimits: %v", err)
	}
	prg, err := rt.CompileValidation(`http.get("https://api.example.test/check", {}).status`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	if _, err := rt.EvalValidation(
		context.Background(),
		prg,
		map[string]string{"rule_id": "rule"},
		nil,
		nil,
		EvalOptions{},
	); err != nil {
		t.Fatalf("first evaluation: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := rt.EvalValidation(
		ctx,
		prg,
		map[string]string{"rule_id": "rule"},
		nil,
		nil,
		EvalOptions{},
	); err == nil {
		t.Fatal("canceled evaluation returned no error")
	}

	targets, _ := recorder.snapshot()
	if got, want := len(targets), 1; got != want {
		t.Fatalf("provider requests = %d, want %d", got, want)
	}
}

func TestCanceledSlowRuleDoesNotReserveFutureGlobalCapacity(t *testing.T) {
	limiter, err := newValidationRequestLimiter(ValidationRequestLimits{
		RequestsPerSecond:       100,
		RequestsPerSecondByRule: map[string]float64{"slow-rule": 1},
	})
	if err != nil {
		t.Fatalf("newValidationRequestLimiter: %v", err)
	}
	if err := limiter.wait(context.Background(), "slow-rule"); err != nil {
		t.Fatalf("first slow-rule wait: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := limiter.wait(ctx, "slow-rule"); err == nil {
		t.Fatal("second slow-rule wait returned no cancellation error")
	}

	start := time.Now()
	if err := limiter.wait(context.Background(), "other-rule"); err != nil {
		t.Fatalf("other-rule wait: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("slow rule reserved global capacity for %s", elapsed)
	}
}

func TestValidationRequestLimitConfigurationRejectsInvalidRates(t *testing.T) {
	tests := []ValidationRequestLimits{
		{MaxRequestsPerTarget: -1},
		{RequestsPerSecond: -1},
		{RequestsPerSecondByRule: map[string]float64{"": 1}},
		{RequestsPerSecondByRule: map[string]float64{"rule": 0}},
	}
	for _, cfg := range tests {
		if _, err := newValidationRequestLimiter(cfg); err == nil {
			t.Fatalf("newValidationRequestLimiter(%#v) returned no error", cfg)
		}
	}
}

func TestValidationRequestTargetNormalizesDefaultPorts(t *testing.T) {
	for _, test := range []struct {
		raw  string
		want string
	}{
		{raw: "https://API.EXAMPLE.TEST:443/v1", want: "https://api.example.test"},
		{raw: "http://API.EXAMPLE.TEST:80/v1", want: "http://api.example.test"},
		{raw: "https://api.example.test:8443/v1", want: "https://api.example.test:8443"},
		{raw: "https://[::1]:443/v1", want: "https://[::1]"},
	} {
		u, err := url.Parse(test.raw)
		if err != nil {
			t.Fatalf("url.Parse(%q): %v", test.raw, err)
		}
		if got := validationRequestTarget(u); got != test.want {
			t.Fatalf("validationRequestTarget(%q) = %q, want %q", test.raw, got, test.want)
		}
	}
}

func runConcurrentValidations(t *testing.T, rt *Runtime, prg Program, ruleID string, count int) {
	t.Helper()
	var wg sync.WaitGroup
	errs := make(chan error, count)
	for range count {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := rt.EvalValidation(
				context.Background(),
				prg,
				map[string]string{"rule_id": ruleID},
				nil,
				nil,
				EvalOptions{},
			)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("evaluation: %v", err)
		}
	}
}

func assertMinimumRequestSpacing(t *testing.T, times []time.Time, minimum time.Duration) {
	t.Helper()
	if len(times) < 2 {
		t.Fatalf("recorded %d request times, want at least 2", len(times))
	}
	sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
	for i := 1; i < len(times); i++ {
		if spacing := times[i].Sub(times[i-1]); spacing < minimum {
			t.Fatalf("request spacing %s is less than %s", spacing, minimum)
		}
	}
}
