package validate

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/betterleaks/betterleaks/internal/exprruntime"
	"github.com/betterleaks/betterleaks/report"
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
	prg, err := rt.CompileValidation(`let r = http.get("` + srv.URL + `", {}); {"result": "valid", "status": r.status}`)
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
	if result.Metadata["resp_status"] != int64(http.StatusAccepted) {
		t.Fatalf("resp_status metadata = %v", result.Metadata["resp_status"])
	}
	if result.Metadata["resp_header_x-trace"] != "seen" {
		t.Fatalf("resp_header_x-trace = %v", result.Metadata["resp_header_x-trace"])
	}
	if result.Metadata["resp_body"] != `{"debug":true}` {
		t.Fatalf("resp_body = %v", result.Metadata["resp_body"])
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

func TestPoolExposesCanonicalAndLegacyComponentBindings(t *testing.T) {
	rt, err := exprruntime.New(nil)
	if err != nil {
		t.Fatalf("exprruntime.New: %v", err)
	}
	prg, err := rt.CompileValidation(`len(finding["captures"]) == 1
&& (finding["captures"]?.primary_group ?? "") == "named-value"
&& len(components) == 1
&& (components["required-component"]?.secret ?? "") == "account"
&& (components["required-component"]?.captures?.kind ?? "") == "tenant"
&& len(captures) == 3
&& captures["primary_group"] == "named-value"
&& captures["required-component"] == "account"
&& captures["required-component:kind"] == "tenant"
? {"result": "valid"} : {"result": "invalid"}`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	emitted := make(chan report.Finding, 1)
	p := NewPool(1, rt)
	p.Emit = func(finding report.Finding) { emitted <- finding }
	p.Submit(report.Finding{
		RuleID:        "primary",
		Secret:        "secret",
		CaptureGroups: map[string]string{"primary_group": "named-value"},
		ComponentSets: []report.ComponentSet{
			{Components: []*report.ComponentFinding{{
				RuleID:        "required-component",
				Secret:        "account",
				CaptureGroups: map[string]string{"kind": "tenant"},
			}}},
		},
	}, prg)
	p.Close()

	got := <-emitted
	if got.Validation.Status != report.ValidationStatusValid {
		t.Fatalf("validation status = %q, want valid (canonical and legacy bindings must both work)", got.Validation.Status)
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
