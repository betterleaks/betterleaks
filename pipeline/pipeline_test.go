package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/betterleaks/betterleaks/v2/analyze"
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/credential"
	"github.com/betterleaks/betterleaks/v2/fingerprint"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/scan"
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestPipeline(cfg *config.Config, options ...scan.Option) (*Pipeline, error) {
	scanner, err := scan.New(cfg, options...)
	if err != nil {
		return nil, err
	}
	analyzer, err := analyze.New(cfg, analyze.WithWorkers(1))
	if err != nil {
		return nil, err
	}
	return New(scanner, analyzer)
}

func mustPipeline(t *testing.T, cfg *config.Config, options ...scan.Option) *Pipeline {
	t.Helper()
	p, err := newTestPipeline(cfg, options...)
	require.NoError(t, err)
	return p
}

type fragmentSource struct {
	fragments []sources.Fragment
	err       error
}

func (s fragmentSource) Fragments(ctx context.Context, yield sources.FragmentsFunc) error {
	for _, fragment := range s.fragments {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := yield(fragment, nil); err != nil {
			return err
		}
	}
	return s.err
}

func testConfig() *config.Config {
	return &config.Config{Rules: []config.Rule{{
		ID:    "test-secret",
		Regex: `secret-[a-z]+`,
	}}}
}

func TestIgnoredFingerprintsSkipProviderRequests(t *testing.T) {
	var requests, ignoredRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Query().Get("secret") == "secret-ignored" {
			ignoredRequests.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	cfg := testConfig()
	cfg.Rules[0].ValidateExpr = fmt.Sprintf(`let r = http.get(%q + "?secret=" + finding["secret"], {}); {"result": r.status == 200 ? "valid" : "error"}`, server.URL)
	cfg.Rules[0].AnalyzeExpr = fmt.Sprintf(`let r = http.get(%q + "?secret=" + finding["secret"], {}); {"capabilities": r.status == 200 ? ["read"] : []}`, server.URL)
	runner := mustPipeline(t, cfg, scan.WithIgnoredFingerprints(fingerprint.Sum([]byte("secret-ignored"))))
	source := fragmentSource{fragments: []sources.Fragment{{Raw: "secret-ignored secret-visible", Attributes: map[string]string{sources.AttrPath: "one.txt"}}, {Raw: "secret-ignored", Attributes: map[string]string{sources.AttrPath: "two.txt"}}}}
	var findings []report.Finding
	summary, err := runner.Scan(t.Context(), source, func(f report.Finding) error {
		findings = append(findings, f)
		return nil
	})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "secret-visible", findings[0].Match.Value)
	assert.Equal(t, report.SeverityMedium, findings[0].Analysis.Severity)
	assert.Equal(t, 1, summary.EmittedFindings)
	assert.Equal(t, map[report.ValidationStatus]int{report.ValidationStatusValid: 1}, summary.ValidationCounts)
	assert.Equal(t, int32(2), requests.Load())
	count := 0
	_, err = runner.Scan(t.Context(), source, func(f report.Finding) error {
		assert.Equal(t, "secret-visible", f.Match.Value)
		count++
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.Equal(t, int32(4), requests.Load())
	assert.Zero(t, ignoredRequests.Load())
}

func TestPipelineScanIsReusableWithValidation(t *testing.T) {
	cfg := testConfig()
	cfg.Rules[0].ValidateExpr = `{"result": "valid"}`
	runner, err := newTestPipeline(cfg)
	require.NoError(t, err)
	require.True(t, runner.ValidationEnabled())

	const content = "secret-alpha"
	for range 2 {
		var findings []report.Finding
		summary, scanErr := runner.Scan(t.Context(), fragmentSource{fragments: []sources.Fragment{{Raw: content}}}, func(finding report.Finding) error {
			findings = append(findings, finding)
			return nil
		})
		require.NoError(t, scanErr)
		require.Len(t, findings, 1)
		assert.Equal(t, report.ValidationStatusValid, findings[0].Analysis.Status)
		assert.Equal(t, uint64(len(content)), summary.BytesInspected)
		assert.Equal(t, 1, summary.EmittedFindings)
		assert.Equal(t, 1, summary.ValidationCounts[report.ValidationStatusValid])
	}
}

func TestScanValidationAndEmptyAnalysisContracts(t *testing.T) {
	for _, test := range []struct {
		name, validation, analysis string
		status                     report.ValidationStatus
		severity                   report.Severity
	}{
		{"missing result", `{"foo": "bar"}`, `{"capabilities": ["admin"]}`, report.ValidationStatusError, report.SeverityNone},
		{"wrong result type", `{"result": 123}`, `{"capabilities": ["admin"]}`, report.ValidationStatusError, report.SeverityNone},
		{"unknown status", `{"result": "bogus"}`, `{"capabilities": ["admin"]}`, report.ValidationStatusError, report.SeverityNone},
		{"intentional unknown", `{"result": "unknown"}`, `{"capabilities": ["admin"]}`, report.ValidationStatusUnknown, report.SeverityNone},
		{"empty analysis", `{"result": "valid"}`, `{}`, report.ValidationStatusValid, report.SeverityUnknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.Rules[0].ValidateExpr = test.validation
			cfg.Rules[0].AnalyzeExpr = test.analysis
			runner, err := newTestPipeline(cfg)
			require.NoError(t, err)
			var findings []report.Finding
			summary, err := runner.Scan(t.Context(), fragmentSource{fragments: []sources.Fragment{{Raw: "secret-alpha"}}}, func(f report.Finding) error {
				findings = append(findings, f)
				return nil
			})
			require.NoError(t, err)
			require.Len(t, findings, 1)
			assert.Equal(t, test.status, findings[0].Analysis.Status)
			assert.Equal(t, 1, summary.ValidationCounts[test.status])
			assert.Equal(t, test.severity, findings[0].Analysis.Severity)
			if test.status == report.ValidationStatusError {
				assert.NotEmpty(t, findings[0].Analysis.StatusReason+findings[0].Analysis.Reason)
			}
			if test.status != report.ValidationStatusValid {
				assert.Empty(t, findings[0].Analysis.Severity, "permission analysis must not run without valid credentials")
				assert.Nil(t, findings[0].Analysis.Identity)
				assert.Empty(t, findings[0].Analysis.Capabilities)
			}
		})
	}
}

func TestPipelineNeverCompilesOrExecutesRevocation(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	for _, expression := range []string{
		fmt.Sprintf(`let response = http.delete(%q, {}); {"result": "revoked"}`, server.URL),
		`invalid revocation syntax ???`,
	} {
		for _, withValidation := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%t", expression, withValidation), func(t *testing.T) {
				cfg := &config.Config{Rules: []config.Rule{{ID: "token", Regex: `(secret-token)`, RevokeExpr: expression}}}
				if withValidation {
					cfg.Rules[0].ValidateExpr = `{"result": "valid"}`
					cfg.Rules[0].AnalyzeExpr = `{"capabilities": ["read"]}`
				}
				scanner, err := scan.New(cfg, scan.WithPrecompile())
				require.NoError(t, err)
				analyzer, err := analyze.New(cfg, analyze.WithPrecompile())
				require.NoError(t, err)
				runner, err := New(scanner, analyzer)
				require.NoError(t, err)
				var findings []report.Finding
				_, err = runner.Scan(t.Context(), fragmentSource{fragments: []sources.Fragment{{Raw: "secret-token"}}}, func(f report.Finding) error {
					findings = append(findings, f)
					return nil
				})
				require.NoError(t, err)
				require.Len(t, findings, 1)
				require.NotEqual(t, report.ValidationStatusRevoked, findings[0].Analysis.Status)
				require.Zero(t, requests.Load())
			})
		}
	}
}

func TestCanonicalCapturesAcrossCredentialStages(t *testing.T) {
	cfg := &config.Config{Rules: []config.Rule{
		{
			ID: "primary", Regex: `(?P<tenant>acme):(?P<key>primary)`, SecretGroup: 2,
			// Inspect this match's captures before any companion is assembled.
			Filter:     `finding.captures.tenant != "acme"`,
			Components: []config.Component{{RuleID: "part"}, {RuleID: "optional", Optional: true}},
			ValidateExpr: `finding.secret == "primary" && finding.captures.tenant == "acme"
&& components["part"].captures.tenant == "companion"
&& (components["optional"]?.secret ?? "absent") == "absent"
? {"result": "valid", "analysis": {"selected": components["part"].secret}}
: {"result": "invalid"}`,
			AnalyzeExpr: `finding.captures.tenant == "acme"
&& components["part"].captures.tenant == "companion"
&& validation.analysis.selected == components["part"].secret
? {"capabilities": components["part"].secret == "readkey" ? ["read"] : ["write"]}
: {"reason": "credential inputs changed between stages"}`,
		},
		{
			ID: "part", Regex: `(?P<tenant>companion|fixture):(?P<key>readkey|writekey)`, SecretGroup: 2,
			Filter: `finding.captures.tenant == "fixture"`, SkipReport: true,
		},
		{ID: "optional", Regex: `optional-key`, SkipReport: true},
	}}
	d := mustPipeline(t, cfg, scan.WithPrecompile())
	var findings []report.Finding
	_, err := d.Scan(t.Context(), &sources.Reader{Content: strings.NewReader(
		"acme:primary companion:readkey companion:writekey fixture:readkey"),
	}, func(f report.Finding) error {
		findings = append(findings, f)
		return nil
	})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	require.Len(t, findings[0].ComponentSets, 2, "component filtering precedes assembly")
	for _, set := range findings[0].ComponentSets {
		require.Equal(t, report.ValidationStatusValid, set.Analysis.Status)
		require.Len(t, set.Components, 1)
		component := set.Components[0]
		validator, err := analyze.New(cfg)
		require.NoError(t, err)
		direct, err := validator.AnalyzeCredential(t.Context(), credential.Input{
			RuleID: "primary", Secret: "primary", Captures: map[string]string{"tenant": "acme"},
			Components: map[string]credential.Component{
				"part": {Secret: component.Match.Value, Captures: map[string]string{"tenant": "companion"}},
			},
		})
		require.NoError(t, err)
		require.Equal(t, set.Analysis.Status, direct.Analysis.Status)
		require.Equal(t, set.Analysis, direct.Analysis)
		want := []report.Capability{report.CapabilityRead}
		if component.Match.Value == "writekey" {
			want = []report.Capability{report.CapabilityWrite}
		}
		require.Equal(t, want, set.Analysis.Capabilities)
	}
}

func TestProviderWorkersAreIndependentAndBounded(t *testing.T) {
	for _, tc := range []struct {
		name    string
		workers int
	}{
		{"one provider worker", 1}, {"three provider workers", 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			workers := tc.workers
			started := make(chan struct{}, workers*2)
			release := make(chan struct{})
			var active, maximum atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := active.Add(1)
				defer active.Add(-1)
				for old := maximum.Load(); n > old; old = maximum.Load() {
					if maximum.CompareAndSwap(old, n) {
						break
					}
				}
				started <- struct{}{}
				select {
				case <-release:
				case <-r.Context().Done():
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			cfg := &config.Config{Rules: []config.Rule{{ID: "token", Regex: `secret-[0-9]+`, ValidateExpr: fmt.Sprintf(`let r = http.get(%q, {}); {"result":"valid"}`, server.URL)}}}
			scanner, err := scan.New(cfg, scan.WithWorkers(1))
			require.NoError(t, err)
			analyzer, err := analyze.New(cfg, analyze.WithWorkers(workers))
			require.NoError(t, err)
			p, err := New(scanner, analyzer)
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			var input strings.Builder
			for i := range workers * 2 {
				fmt.Fprintf(&input, "secret-%d ", i)
			}
			done := make(chan error, 1)
			go func() {
				summary, err := p.Scan(ctx, &sources.Reader{Content: strings.NewReader(input.String())}, nil)
				if err == nil && summary.EmittedFindings != workers*2 {
					err = fmt.Errorf("got %d findings", summary.EmittedFindings)
				}
				done <- err
			}()
			for range workers {
				select {
				case <-started:
				case <-ctx.Done():
					t.Fatal("provider work was serialized behind the single scan worker")
				}
			}
			unblock()
			require.NoError(t, <-done)
			require.Equal(t, int32(workers), maximum.Load())
		})
	}
}

type producingSource struct {
	produced atomic.Int32
	stopped  chan struct{}
}

func (s *producingSource) Fragments(ctx context.Context, yield sources.FragmentsFunc) error {
	defer close(s.stopped)
	for i := range 100000 {
		if err := ctx.Err(); err != nil {
			return err
		}
		s.produced.Add(1)
		if err := yield(sources.Fragment{Raw: fmt.Sprintf("secret-%d", i)}, nil); err != nil {
			return err
		}
	}
	return nil
}

func TestHandlerFailureCancelsAndJoinsWorkers(t *testing.T) {
	cfg := &config.Config{Rules: []config.Rule{{ID: "token", Regex: `secret-[0-9]+`, ValidateExpr: `{"result":"valid"}`}}}
	p := mustPipeline(t, cfg, scan.WithWorkers(1))
	source := &producingSource{stopped: make(chan struct{})}
	want := errors.New("storage failed")
	var calls int
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	summary, err := p.Scan(ctx, source, func(report.Finding) error { calls++; return want })
	require.ErrorIs(t, err, want)
	require.Equal(t, 1, calls)
	require.Equal(t, 1, summary.EmittedFindings)
	require.Less(t, source.produced.Load(), int32(1000), "bounded queues must propagate backpressure")
	select {
	case <-source.stopped:
	default:
		t.Fatal("source still running after Scan returned")
	}
}

func TestPipelineValidationPolicy(t *testing.T) {
	const validation = `{"result": finding.secret == "secret-live" ? "valid" : "invalid"}`
	for _, tc := range []struct {
		name                 string
		validation, analysis string
		noAnalyzer           bool
		options              []Option
		wantEmitted          int
		wantCounts           map[report.ValidationStatus]int
		wantError            string
	}{
		{name: "all statuses", validation: validation, wantEmitted: 2, wantCounts: map[report.ValidationStatus]int{report.ValidationStatusValid: 1, report.ValidationStatusInvalid: 1}},
		{name: "valid only", validation: validation, options: []Option{WithValidationStatuses(report.ValidationStatusValid)}, wantEmitted: 1, wantCounts: map[report.ValidationStatus]int{report.ValidationStatusValid: 1, report.ValidationStatusInvalid: 1}},
		{name: "validation only ignores analysis", validation: validation, analysis: "invalid analysis syntax ???", options: []Option{WithValidationOnly(), WithValidationStatuses(report.ValidationStatusValid)}, wantEmitted: 1, wantCounts: map[report.ValidationStatus]int{report.ValidationStatusValid: 1, report.ValidationStatusInvalid: 1}},
		{name: "no analyzer", validation: validation, noAnalyzer: true, wantEmitted: 2, wantCounts: map[report.ValidationStatus]int{report.ValidationStatusNone: 2}},
		{name: "unchecked excluded by valid filter", options: []Option{WithValidationStatuses(report.ValidationStatusValid)}, wantEmitted: 0, wantCounts: map[report.ValidationStatus]int{report.ValidationStatusNone: 2}},
		{name: "invalid status", options: []Option{WithValidationStatuses("surprising")}, wantError: "invalid validation status"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.Rules[0].ValidateExpr, cfg.Rules[0].AnalyzeExpr = tc.validation, tc.analysis
			scanner, err := scan.New(cfg, scan.WithPrecompile())
			require.NoError(t, err)
			var analyzer *analyze.Analyzer
			if !tc.noAnalyzer {
				analyzer, err = analyze.New(cfg)
				require.NoError(t, err)
			}
			p, err := New(scanner, analyzer, tc.options...)
			if tc.wantError != "" {
				require.ErrorContains(t, err, tc.wantError)
				return
			}
			require.NoError(t, err)
			emitted := 0
			summary, err := p.Scan(t.Context(), &sources.Reader{Content: strings.NewReader("secret-live secret-fixture")}, func(report.Finding) error { emitted++; return nil })
			require.NoError(t, err)
			require.Equal(t, 2, summary.DetectedFindings)
			require.Equal(t, tc.wantEmitted, summary.EmittedFindings)
			require.Equal(t, tc.wantEmitted, emitted)
			require.Equal(t, tc.wantCounts, summary.ValidationCounts)
		})
	}
}

func TestExplicitContextSurvivesHandoff(t *testing.T) {
	cfg := testConfig()
	cfg.Rules[0].ValidateExpr = `finding.secret == "secret-alpha" ? {"result":"valid","analysis":{"owner":"acme"}} : {"result":"invalid"}`
	cfg.Rules[0].AnalyzeExpr = `{"identity":{"id":validation.analysis.owner},"capabilities":["read"]}`
	p := mustPipeline(t, cfg, scan.WithMatchContext("2L"))
	var finding report.Finding
	_, err := p.Scan(t.Context(), &sources.Reader{Content: strings.NewReader("tenant=acme\nsecret-alpha"), Attributes: map[string]string{sources.AttrPath: "archive.zip!app.env"}}, func(f report.Finding) error { finding = f; return nil })
	require.NoError(t, err)
	require.Equal(t, report.ValidationStatusValid, finding.Analysis.Status)
	require.Equal(t, "archive.zip!app.env", finding.Location.Path)
	require.NotContains(t, finding.Attributes, sources.AttrPath)
	require.Equal(t, "acme", finding.Analysis.Identity.ID)
	require.Empty(t, finding.Analysis.Metadata, "private validation evidence must not enter reports")
	require.Equal(t, "tenant=acme\nsecret-alpha", finding.MatchContext)
	// Explicit context survives serialization without hidden finding state.
	encoded, err := json.Marshal(finding)
	require.NoError(t, err)
	var restored report.Finding
	require.NoError(t, json.Unmarshal(encoded, &restored))
	analyzer, err := analyze.New(cfg)
	require.NoError(t, err)
	resolved, err := analyzer.Analyze(t.Context(), restored)
	require.NoError(t, err)
	require.Equal(t, finding.Analysis, resolved.Analysis)
}

func TestCancellationInterruptsProviderRequests(t *testing.T) {
	started := make(chan struct{})
	stopped := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(stopped)
	}))
	defer server.Close()
	cfg := testConfig()
	cfg.Rules[0].ValidateExpr = fmt.Sprintf(`let r = http.get(%q, {}); {"result":"valid"}`, server.URL)
	p := mustPipeline(t, cfg)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := p.Scan(ctx, &sources.Reader{Content: strings.NewReader("secret-alpha")}, nil)
		done <- err
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("provider did not start")
	}
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("pipeline did not stop")
	}
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("provider request was not canceled")
	}
}
