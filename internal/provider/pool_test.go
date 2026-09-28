package provider

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/betterleaks/betterleaks/v2/internal/exprruntime"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPoolDebugMetadata(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("X-Trace", "seen")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"debug":true}`))
	}))
	defer srv.Close()

	rt, err := exprruntime.New(srv.Client())
	if err != nil {
		t.Fatalf("exprruntime.New: %v", err)
	}
	prg, err := rt.CompileValidation(`let r = http.get("` + srv.URL + `", {}); {"result": "valid", "metadata": {"status": r.status}}`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	p := NewPool(1, rt)
	defer p.Close()
	p.Debug = true

	finding := map[string]string{"secret": "secret"}
	result, err := p.evalWithCaptures(prg, "rule", "secret", finding, nil, nil)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if result.Metadata["status"] != int64(http.StatusAccepted) {
		t.Fatalf("status metadata = %v", result.Metadata["status"])
	}
	if result.Debug["resp_status"] != int64(http.StatusAccepted) {
		t.Fatalf("resp_status metadata = %v", result.Debug["resp_status"])
	}
	if result.Debug["resp_header_x-trace"] != "seen" {
		t.Fatalf("resp_header_x-trace = %v", result.Debug["resp_header_x-trace"])
	}
	if result.Debug["resp_body"] != `{"debug":true}` {
		t.Fatalf("resp_body = %v", result.Debug["resp_body"])
	}

	if _, err := p.evalWithCaptures(prg, "rule", "secret", finding, nil, nil); err != nil {
		t.Fatalf("second eval: %v", err)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("debug validation requests = %d, want 2", got)
	}
}

type validationRoundTripFunc func(*http.Request) (*http.Response, error)

func (f validationRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestPoolMaxRequestsReturnsNeedsValidationMetadataAndDoesNotCountCacheHits(t *testing.T) {
	var requests atomic.Int32
	client := &http.Client{Transport: validationRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests.Add(1)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
			Request:    req,
		}, nil
	})}
	rt, err := exprruntime.New(client)
	if err != nil {
		t.Fatalf("exprruntime.New: %v", err)
	}
	if err := rt.SetValidationRequestLimits(exprruntime.ValidationRequestLimits{
		MaxRequestsPerTarget: 1,
	}); err != nil {
		t.Fatalf("SetValidationRequestLimits: %v", err)
	}
	prg, err := rt.CompileValidation(
		`let r = http.get("https://api.example.test/check", {}); ` +
			`r.status == 200 ? {"result": "valid"} : {"result": "unknown"}`,
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	p := NewPool(1, rt)
	defer p.Close()
	finding := map[string]string{"rule_id": "example-rule", "secret": "secret-a"}

	first, err := p.evalWithCaptures(prg, "example-rule", "secret-a", finding, nil, nil)
	if err != nil {
		t.Fatalf("first eval: %v", err)
	}
	if first.Status != report.ValidationStatusValid {
		t.Fatalf("first status = %q, want valid", first.Status)
	}

	cached, err := p.evalWithCaptures(prg, "example-rule", "secret-a", finding, nil, nil)
	if err != nil {
		t.Fatalf("cached eval: %v", err)
	}
	if cached.Status != report.ValidationStatusValid {
		t.Fatalf("cached status = %q, want valid", cached.Status)
	}

	finding["secret"] = "secret-b"
	blocked, err := p.evalWithCaptures(prg, "example-rule", "secret-b", finding, nil, nil)
	if err != nil {
		t.Fatalf("blocked eval: %v", err)
	}
	if blocked.Status != report.ValidationStatusNeedsValidation {
		t.Fatalf("blocked status = %q, want needs_validation", blocked.Status)
	}
	if blocked.Metadata["betterleaks_max_requests_hit"] != true {
		t.Fatalf("max request metadata = %#v", blocked.Metadata)
	}
	if blocked.Metadata["betterleaks_validation_target"] != "https://api.example.test" {
		t.Fatalf("target metadata = %#v", blocked.Metadata["betterleaks_validation_target"])
	}
	if blocked.Metadata["betterleaks_validation_max_requests"] != 1 {
		t.Fatalf("max metadata = %#v", blocked.Metadata["betterleaks_validation_max_requests"])
	}
	if blocked.Metadata["betterleaks_validation_requests_sent"] != 1 {
		t.Fatalf("sent metadata = %#v", blocked.Metadata["betterleaks_validation_requests_sent"])
	}
	if blocked.Metadata["betterleaks_validation_rule_id"] != "example-rule" {
		t.Fatalf("rule metadata = %#v", blocked.Metadata["betterleaks_validation_rule_id"])
	}
	if got, want := requests.Load(), int32(1); got != want {
		t.Fatalf("provider requests = %d, want %d", got, want)
	}
}

func TestPoolExposesCanonicalComponentBindings(t *testing.T) {
	rt, err := exprruntime.New(nil)
	if err != nil {
		t.Fatalf("exprruntime.New: %v", err)
	}
	prg, err := rt.CompileValidation(`len(finding["captures"]) == 1
&& (finding["captures"]?.primary_group ?? "") == "named-value"
&& len(components) == 1
&& (components["required-component"]?.secret ?? "") == "account"
&& (components["required-component"]?.captures?.kind ?? "") == "tenant"
? {"result": "valid"} : {"result": "invalid"}`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	emitted := make(chan report.Finding, 1)
	p := NewPool(1, rt)
	p.Emit = func(finding report.Finding) { emitted <- finding }
	p.Submit(report.Finding{
		RuleID: "primary",
		Match:  report.Match{Value: "secret", Captures: map[string]string{"primary_group": "named-value"}},

		ComponentSets: []report.ComponentSet{
			{Components: []report.ComponentFinding{{
				RuleID: "required-component",
				Match:  report.Match{Value: "account", Captures: map[string]string{"kind": "tenant"}},
			}}},
		},
	}, prg)
	p.Close()

	got := <-emitted
	if got.Analysis.Status != report.ValidationStatusValid {
		t.Fatalf("validation status = %q, want valid (canonical and legacy bindings must both work)", got.Analysis.Status)
	}
}

func TestCacheKeyIncludesComponentCombination(t *testing.T) {
	withoutOptional := CacheKey("primary", "secret", nil, map[string]cacheComponent{
		"required": {Secret: "account"},
	})
	withOptional := CacheKey("primary", "secret", nil, map[string]cacheComponent{
		"required": {Secret: "account"},
		"optional": {Secret: "session"},
	})
	if withoutOptional == withOptional {
		t.Fatal("cache keys for distinct component combinations must differ")
	}
}

func TestCacheKeySeparatesCapturesAndComponents(t *testing.T) {
	capture := CacheKey("primary", "secret", map[string]string{"shared": "value"}, nil)
	component := CacheKey("primary", "secret", nil, map[string]cacheComponent{"shared": {Secret: "value"}})
	if capture == component {
		t.Fatal("capture and component values must occupy separate cache-key namespaces")
	}
}

func TestCacheKeyIncludesComponentCaptures(t *testing.T) {
	first := CacheKey("primary", "secret", nil, map[string]cacheComponent{
		"component": {Secret: "value", Captures: map[string]string{"group": "one"}},
	})
	second := CacheKey("primary", "secret", nil, map[string]cacheComponent{
		"component": {Secret: "value", Captures: map[string]string{"group": "two"}},
	})
	if first == second {
		t.Fatal("component named capture groups must contribute to the validation cache key")
	}
}

func TestPoolDeduplicatesFailedCombinationsWithinFinding(t *testing.T) {
	var requests atomic.Int32
	rt, err := exprruntime.New(&http.Client{Transport: validationRoundTripFunc(func(*http.Request) (*http.Response, error) {
		requests.Add(1)
		return nil, errors.New("provider unavailable")
	})})
	if err != nil {
		t.Fatal(err)
	}
	program, err := rt.CompileValidation(`let r = http.get("https://provider.invalid/check", {}); {"result":"valid"}`)
	if err != nil {
		t.Fatal(err)
	}
	pool := NewPoolContext(t.Context(), 1, rt)
	results := make(chan report.Finding, 2)
	pool.Emit = func(f report.Finding) { results <- f }
	finding := report.Finding{RuleID: "test", Match: report.Match{Value: "primary"}, ComponentSets: []report.ComponentSet{
		{Components: []report.ComponentFinding{{RuleID: "part", Match: report.Match{Value: "companion"}, Location: report.Location{StartLine: 1}}}},
		{Components: []report.ComponentFinding{{RuleID: "part", Match: report.Match{Value: "companion"}, Location: report.Location{StartLine: 2}}}},
	}}
	for range 2 {
		if err := pool.SubmitContext(t.Context(), finding, program); err != nil {
			t.Fatal(err)
		}
	}
	pool.Close()
	if got := requests.Load(); got != 2 {
		t.Fatalf("provider requests = %d, want one per finding", got)
	}
	for range 2 {
		result := <-results
		if result.Analysis.Status != report.ValidationStatusError || len(result.ComponentSets) != 2 {
			t.Fatalf("unexpected failed result: status=%s sets=%d", result.Analysis.Status, len(result.ComponentSets))
		}
	}
}

func TestPoolAnalyzesValidCredential(t *testing.T) {
	runtime, err := exprruntime.New(nil)
	require.NoError(t, err)
	validationProgram, err := runtime.CompileValidation(`{
		"result": "valid",
		"analysis": {"owner": "credential=" + finding["secret"]}
	}`)
	require.NoError(t, err)
	analysisProgram, err := runtime.CompileAnalysis(`{
		"reason": validation["analysis"]["owner"],
		"identity": {"id": validation["analysis"]["owner"]},
		"capabilities": ["write", "read", "write"]
	}`)
	require.NoError(t, err)

	pool := NewPoolContext(t.Context(), 1, runtime)
	results := make(chan report.Finding, 2)
	pool.Emit = func(finding report.Finding) { results <- finding }
	finding := report.Finding{
		RuleID: "test-rule",
		Match:  report.Match{Value: "secret-value", Full: "secret-value"},
	}
	require.NoError(t, pool.SubmitWithAnalysisContext(t.Context(), finding, validationProgram, analysisProgram))
	require.NoError(t, pool.SubmitWithAnalysisContext(t.Context(), finding, validationProgram, analysisProgram))
	pool.Close()

	for range 2 {
		result := <-results
		assert.Equal(t, report.ValidationStatusValid, result.Analysis.Status)
		assert.Empty(t, result.Analysis.Metadata)
		assert.Equal(t, report.SeverityHigh, result.Analysis.Severity)
		assert.Equal(t, []report.Capability{report.CapabilityRead, report.CapabilityWrite}, result.Analysis.Capabilities)
		require.NotNil(t, result.Analysis.Identity)
		assert.Equal(t, "credential=[redacted]", result.Analysis.Identity.ID)
		assert.Equal(t, "credential=[redacted]", result.Analysis.Reason)
	}
	hits, misses := pool.AnalysisStats()
	assert.Equal(t, uint64(1), hits)
	assert.Equal(t, uint64(1), misses)
}

func TestPoolSkipsAnalysisWhenValidationIsNotValid(t *testing.T) {
	runtime, err := exprruntime.New(nil)
	require.NoError(t, err)
	validationProgram, err := runtime.CompileValidation(`{"result": "invalid"}`)
	require.NoError(t, err)
	analysisProgram, err := runtime.CompileAnalysis(`{"capabilities": ["admin"]}`)
	require.NoError(t, err)

	pool := NewPoolContext(t.Context(), 1, runtime)
	results := make(chan report.Finding, 1)
	pool.Emit = func(finding report.Finding) { results <- finding }
	require.NoError(t, pool.SubmitWithAnalysisContext(t.Context(), report.Finding{
		RuleID: "test-rule",
		Match:  report.Match{Value: "secret-value"},
	}, validationProgram, analysisProgram))
	pool.Close()

	result := <-results
	assert.Equal(t, report.ValidationStatusInvalid, result.Analysis.Status)
	assert.Equal(t, report.Analysis{Status: report.ValidationStatusInvalid}, result.Analysis)
	_, misses := pool.AnalysisStats()
	assert.Zero(t, misses)
}

func TestPoolAnalysisFailurePreservesValidCredential(t *testing.T) {
	runtime, err := exprruntime.New(nil)
	require.NoError(t, err)
	validationProgram, err := runtime.CompileValidation(`{"result": "valid"}`)
	require.NoError(t, err)
	analysisProgram, err := runtime.CompileAnalysis(`{"severity": "high"}`)
	require.NoError(t, err)

	pool := NewPoolContext(t.Context(), 1, runtime)
	results := make(chan report.Finding, 2)
	pool.Emit = func(finding report.Finding) { results <- finding }
	finding := report.Finding{
		RuleID: "test-rule",
		Match:  report.Match{Value: "secret-value"},
	}
	require.NoError(t, pool.SubmitWithAnalysisContext(t.Context(), finding, validationProgram, analysisProgram))
	require.NoError(t, pool.SubmitWithAnalysisContext(t.Context(), finding, validationProgram, analysisProgram))
	pool.Close()

	for range 2 {
		result := <-results
		assert.Equal(t, report.ValidationStatusValid, result.Analysis.Status)
		assert.Equal(t, report.SeverityUnknown, result.Analysis.Severity)
		assert.Contains(t, result.Analysis.Reason, "unknown field")
	}
	hits, misses := pool.AnalysisStats()
	assert.Zero(t, hits)
	assert.Equal(t, uint64(2), misses)
}

func TestPoolAnalyzesValidComponentSets(t *testing.T) {
	runtime, err := exprruntime.New(nil)
	require.NoError(t, err)
	validationProgram, err := runtime.CompileValidation(`{
		"result": components["account"]?.secret == "account-secret" ? "valid" : "invalid",
		"analysis": {"owner": "user-1"}
	}`)
	require.NoError(t, err)
	analysisProgram, err := runtime.CompileAnalysis(`{
		"identity": {
			"id": validation["analysis"]["owner"],
			"account": {"id": components["account"].secret}
		},
		"capabilities": ["read"]
	}`)
	require.NoError(t, err)

	pool := NewPoolContext(t.Context(), 1, runtime)
	results := make(chan report.Finding, 1)
	pool.Emit = func(finding report.Finding) { results <- finding }
	require.NoError(t, pool.SubmitWithAnalysisContext(t.Context(), report.Finding{
		RuleID: "test-rule",
		Match:  report.Match{Value: "primary-secret"},
		ComponentSets: []report.ComponentSet{{Components: []report.ComponentFinding{{
			RuleID: "account",
			Match:  report.Match{Value: "account-secret"},
		}}}},
	}, validationProgram, analysisProgram))
	pool.Close()

	result := <-results
	require.Len(t, result.ComponentSets, 1)
	set := result.ComponentSets[0]
	assert.Equal(t, report.SeverityMedium, set.Analysis.Severity)
	require.NotNil(t, set.Analysis.Identity)
	require.NotNil(t, set.Analysis.Identity.Account)
	assert.Equal(t, "[redacted]", set.Analysis.Identity.Account.ID)
	assert.Equal(t, set.Analysis, result.Analysis)
}

func TestCompositeAnalysisRollupUsesOneCombination(t *testing.T) {
	runtime, err := exprruntime.New(nil)
	require.NoError(t, err)
	validate, err := runtime.CompileValidation(`
 let label = components.account.captures.label;
 {
   "result": label == "invalid" ? "invalid" : "valid",
   "reason": "accepted " + label,
   "analysis": {"owner":label, "private":"unexported-evidence"},
   "metadata": {"tenant": label, "shared": "from validation"}
 }
 `)
	require.NoError(t, err)
	enrich, err := runtime.CompileAnalysis(`
 let owner = validation.analysis.owner;
 {"reason":"permissions for " + owner, "identity":{"username":owner},
 "capabilities": owner == "admin" ? ["admin"] : ["read"],
 "metadata":{"shared":"from analysis", "permissions_for":owner}}
 `)
	require.NoError(t, err)
	finding := report.Finding{RuleID: "test", Match: report.Match{Value: "primary-credential"}}
	for _, label := range []string{"reader", "invalid", "admin"} {
		finding.ComponentSets = append(finding.ComponentSets, report.ComponentSet{Components: []report.ComponentFinding{{RuleID: "account", Match: report.Match{Value: "credential-" + label, Captures: map[string]string{"label": label}}}}})
	}
	pool := NewPoolContext(t.Context(), 1, runtime)
	results := make(chan report.Finding, 2)
	pool.Emit = func(f report.Finding) { results <- f }
	for range 2 {
		require.NoError(t, pool.SubmitWithAnalysisContext(t.Context(), finding, validate, enrich))
	}
	pool.Close()
	first, second := <-results, <-results
	require.Len(t, first.ComponentSets, 2)
	require.Equal(t, report.ValidationStatusValid, first.Analysis.Status)
	require.Equal(t, report.SeverityHigh, first.Analysis.Severity)
	require.Equal(t, "[redacted]", first.Analysis.Identity.Username)
	require.Equal(t, "accepted [redacted]", first.Analysis.StatusReason)
	require.Equal(t, "permissions for [redacted]", first.Analysis.Reason)
	require.Equal(t, map[string]any{"tenant": "[redacted]", "shared": "from validation"}, first.Analysis.StatusMetadata)
	require.Equal(t, map[string]any{"shared": "from analysis", "permissions_for": "[redacted]"}, first.Analysis.Metadata)
	require.Equal(t, first.ComponentSets[1].Analysis, first.Analysis)
	encoded, err := json.Marshal(first)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "unexported-evidence")
	require.True(t, finding.Analysis.IsZero())
	require.True(t, finding.ComponentSets[0].Analysis.IsZero())
	first.Analysis.StatusMetadata["tenant"] = "changed"
	first.Analysis.Identity.Username = "changed"
	first.Analysis.Capabilities[0] = report.CapabilityRead
	require.Equal(t, "[redacted]", second.Analysis.StatusMetadata["tenant"])
	require.Equal(t, "[redacted]", second.Analysis.Identity.Username)
	require.Equal(t, []report.Capability{report.CapabilityAdmin}, second.Analysis.Capabilities)
}

func TestProviderDebugIsRedactedInFinding(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(w, r.Body)
	}))
	t.Cleanup(server.Close)
	runtime, err := exprruntime.New(server.Client())
	require.NoError(t, err)
	program, err := runtime.CompileValidation(fmt.Sprintf(`
		let response = http.post(%q + "?token=" + finding["secret"], {}, finding["secret"]);
		{"result": "valid", "reason": response.body}
	`, server.URL))
	require.NoError(t, err)
	pool := NewPoolContext(t.Context(), 1, runtime)
	pool.Debug = true
	results := make(chan report.Finding, 1)
	pool.Emit = func(f report.Finding) { results <- f }
	const secret = "synthetic-debug-credential"
	require.NoError(t, pool.SubmitContext(t.Context(), report.Finding{
		RuleID: "debug-test", Match: report.Match{Value: secret},
	}, program))
	pool.Close()
	finding := <-results
	require.Equal(t, report.ValidationStatusValid, finding.Analysis.Status)
	diagnostics := finding.Analysis.Debug["validation"].(map[string]any)
	require.Contains(t, diagnostics["req_url"], "[redacted]")
	require.Equal(t, "[redacted]", diagnostics["req_body"])
	require.Equal(t, "[redacted]", diagnostics["resp_body"])
	require.Empty(t, finding.Analysis.Metadata)
	redacted := finding.RedactedCopy(100)
	encoded, err := json.Marshal(redacted)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), secret)
	require.Equal(t, "[redacted]", redacted.Analysis.StatusReason)
}
