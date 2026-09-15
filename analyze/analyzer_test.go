package analyze

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/credential"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/scan"
	"github.com/betterleaks/betterleaks/v2/sources"
)

func mustNew(t *testing.T, cfg *config.Config, options ...Option) *Analyzer {
	t.Helper()
	validator, err := New(cfg, options...)
	require.NoError(t, err)
	return validator
}

func TestNew(t *testing.T) {
	cfg := &config.Config{Rules: []config.Rule{{ID: "key", Regex: "key", ValidateExpr: `{"result":"valid"}`}}}
	for _, tc := range []struct {
		name      string
		config    *config.Config
		options   []Option
		wantError string
	}{
		{name: "defaults", config: cfg},
		{name: "nil config", wantError: "config is required"},
		{name: "duplicate rule", config: &config.Config{Rules: []config.Rule{cfg.Rules[0], cfg.Rules[0]}}, wantError: "duplicate rule ID"},
		{name: "zero option", config: cfg, options: []Option{{}}, wantError: "option is invalid"},
		{name: "negative workers", config: cfg, options: []Option{WithWorkers(-1)}, wantError: "non-negative"},
		{name: "negative timeout", config: cfg, options: []Option{WithTimeout(-time.Second)}, wantError: "non-negative"},
		{name: "negative budget", config: cfg, options: []Option{WithMaxRequestsPerTarget(-1)}, wantError: "non-negative"},
		{name: "negative rate", config: cfg, options: []Option{WithRequestsPerSecond(-1)}, wantError: "request limits"},
		{name: "NaN rate", config: cfg, options: []Option{WithRequestsPerSecond(math.NaN())}, wantError: "request limits"},
		{name: "infinite rate", config: cfg, options: []Option{WithRequestsPerSecond(math.Inf(1))}, wantError: "request limits"},
		{name: "invalid rule rate", config: cfg, options: []Option{WithRequestsPerSecondByRule(map[string]float64{"key": 0})}, wantError: "request limits"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.config, tc.options...)
			if tc.wantError != "" {
				require.ErrorContains(t, err, tc.wantError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestAnalyzerCopiesConfig(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*config.Config)
	}{
		{"rule ID", func(cfg *config.Config) { cfg.Rules[0].ID = "changed" }},
		{"validation program", func(cfg *config.Config) { cfg.Rules[0].ValidateExpr = `{"result":"invalid"}` }},
		{"component rule", func(cfg *config.Config) { cfg.Rules[0].Components[0].RuleID = "changed" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{Rules: []config.Rule{
				{ID: "key", Regex: "key", Components: []config.Component{{RuleID: "part"}},
					ValidateExpr: `{"result": components.part.secret == "companion" ? "valid" : "invalid"}`},
				{ID: "part", Regex: "part"},
			}}
			analyzer := mustNew(t, cfg)
			// Mutate the caller's data before the first lazy compilation.
			tc.mutate(cfg)
			result, err := analyzer.ValidateCredential(t.Context(), credential.Input{RuleID: "key", Secret: "input", Components: map[string]credential.Component{"part": {Secret: "companion"}}})
			require.NoError(t, err)
			require.Equal(t, report.ValidationStatusValid, result.Analysis.Status)
		})
	}
}

func TestProviderCompilationErrors(t *testing.T) {
	for _, tc := range []struct{ name, validation, analysis, wantError string }{
		{"validation", `???`, ``, "validation"},
		{"analysis", `{"result":"valid"}`, `???`, "analysis"},
	} {
		for _, mode := range []struct {
			name    string
			options []Option
		}{
			{name: "lazy"}, {name: "precompiled", options: []Option{WithPrecompile()}},
		} {
			t.Run(tc.name+"/"+mode.name, func(t *testing.T) {
				cfg := &config.Config{Rules: []config.Rule{{ID: "key", Regex: "key", ValidateExpr: tc.validation, AnalyzeExpr: tc.analysis}}}
				analyzer, err := New(cfg, mode.options...)
				if len(mode.options) == 0 {
					require.NoError(t, err)
					_, err = analyzer.AnalyzeCredential(t.Context(), credential.Input{RuleID: "key", Secret: "secret"})
				}
				require.ErrorContains(t, err, tc.wantError)
			})
		}
	}
}

func TestCredentialCallErrors(t *testing.T) {
	analyzer := mustNew(t, &config.Config{Rules: []config.Rule{{ID: "key", Regex: "key", ValidateExpr: `{"result":"valid"}`}}})
	for _, tc := range []struct {
		name      string
		analyzer  *Analyzer
		ctx       context.Context
		wantError string
	}{
		{"nil analyzer", nil, t.Context(), "must be constructed"},
		{"zero analyzer", &Analyzer{}, t.Context(), "must be constructed"},
		{"nil context", analyzer, nil, "context must not be nil"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.analyzer.ValidateCredential(tc.ctx, credential.Input{RuleID: "key", Secret: "secret"})
			require.ErrorContains(t, err, tc.wantError)
		})
	}
}

func TestValidateCredentialHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (*Analyzer)(nil).ValidateCredential(ctx, credential.Input{})
	require.ErrorIs(t, err, context.Canceled)
}

func TestValidateCredentialPipeline(t *testing.T) {
	for _, tc := range []struct {
		name, validation, analysis string
		enabled                    bool
		status                     report.ValidationStatus
		severity                   report.Severity
		username                   string
		wantReason                 bool
	}{
		{"validation only", `{"result":"valid"}`, `invalid syntax ???`, false, report.ValidationStatusValid, report.SeverityNone, "", false},
		{"analysis", `{"result":"valid","analysis":{"owner":"demo-user"}}`, `{"identity":{"username":validation["analysis"]["owner"]},"capabilities":["write"]}`, true, report.ValidationStatusValid, report.SeverityHigh, "demo-user", false},
		{"no analyzer", `{"result":"valid"}`, ``, true, report.ValidationStatusValid, report.SeverityNone, "", false},
		{"empty analysis", `{"result":"valid"}`, `{}`, true, report.ValidationStatusValid, report.SeverityUnknown, "", false},
		{"invalid skips analysis", `{"result":"invalid"}`, `{"capabilities":["admin"]}`, true, report.ValidationStatusInvalid, report.SeverityNone, "", false},
		{"revoked", `{"result":"revoked"}`, `{}`, true, report.ValidationStatusRevoked, report.SeverityNone, "", false},
		{"malformed validation", `{"result":123}`, `{}`, true, report.ValidationStatusError, report.SeverityNone, "", false},
		{"analysis failure preserves validation", `{"result":"valid"}`, `{"capabilities":123}`, true, report.ValidationStatusValid, report.SeverityUnknown, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{Prefilter: "invalid scan syntax ???", Filter: "invalid scan syntax ???", Rules: []config.Rule{{
				ID: "credential", Regex: `never-matches-this-input`, Filter: "invalid scan syntax ???", Confidence: "low", SkipReport: true,
				ValidateExpr: tc.validation, AnalyzeExpr: tc.analysis,
			}}}
			d := mustNew(t, cfg)
			resolve := d.ValidateCredential
			if tc.enabled {
				resolve = d.AnalyzeCredential
			}
			result, err := resolve(t.Context(), credential.Input{RuleID: "credential", Secret: "raw-secret"})
			require.NoError(t, err)
			assert.Equal(t, tc.status, result.Analysis.Status)
			assert.Equal(t, tc.severity, result.Analysis.Severity)
			if tc.username != "" {
				require.NotNil(t, result.Analysis.Identity)
				assert.Equal(t, tc.username, result.Analysis.Identity.Username)
			}
			if tc.wantReason {
				assert.NotEmpty(t, result.Analysis.Reason)
			}
		})
	}
}

func TestValidateCredentialInputs(t *testing.T) {
	cfg := &config.Config{Rules: []config.Rule{
		{ID: "primary", Regex: `(?P<tenant>tenant)-(?P<secret>key)`, SecretGroup: 2, ValidateExpr: `{"result":"valid"}`, AnalyzeExpr: `{"identity":{"id":finding.captures["tenant"]}}`, Components: []config.Component{{RuleID: "part"}, {RuleID: "optional", Optional: true}}},
		{ID: "part", Regex: `part`}, {ID: "optional", Regex: `optional`},
	}}
	d := mustNew(t, cfg)
	for _, tc := range []struct {
		name  string
		input credential.Input
		want  string
	}{
		{"unknown rule", credential.Input{RuleID: "missing", Secret: "key"}, "not found"},
		{"no validator", credential.Input{RuleID: "part", Secret: "key"}, "does not define validation"},
		{"empty secret", credential.Input{RuleID: "primary"}, "must not be empty"},
		{"large secret", credential.Input{RuleID: "primary", Secret: strings.Repeat("s", (1<<20)+1)}, "exceeds"},
		{"analysis capture missing", credential.Input{RuleID: "primary", Secret: "key"}, "missing required capture(s)"},
		{"component missing", credential.Input{RuleID: "primary", Secret: "key", Captures: map[string]string{"tenant": "demo"}}, "missing required component(s): part"},
		{"extra component", credential.Input{RuleID: "primary", Secret: "key", Captures: map[string]string{"tenant": "demo"}, Components: map[string]credential.Component{"part": {Secret: "x"}, "extra": {Secret: "y"}}}, "not declared"},
		{"empty component", credential.Input{RuleID: "primary", Secret: "key", Captures: map[string]string{"tenant": "demo"}, Components: map[string]credential.Component{"part": {}}}, "must not be empty"},
		{"empty capture name", credential.Input{RuleID: "primary", Secret: "key", Captures: map[string]string{"": "value"}}, "capture name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := d.AnalyzeCredential(t.Context(), tc.input)
			require.ErrorContains(t, err, tc.want)
		})
	}

}

func TestValidateCredentialComponentsAndRedaction(t *testing.T) {
	cfg := &config.Config{Rules: []config.Rule{
		{ID: "key", Regex: `key`, ValidateExpr: `finding["secret"] == " raw-secret\n" && finding.captures["tenant"] == "private-tenant" && components["part"].secret == "companion-secret" && components["part"].captures["region"] == "private-region" ? {"result":"valid", "reason":finding["secret"], "analysis":{"owner":"demo-user"}, "metadata": {"echo":components["part"].captures["region"]}} : {"result":"invalid"}`,
			AnalyzeExpr: `{"identity":{"username":validation["analysis"]["owner"]},"capabilities":["read"],"metadata":{"echo":finding.captures["tenant"]+components["part"].secret}}`,
			Components:  []config.Component{{RuleID: "part"}, {RuleID: "optional", Optional: true}}},
		{ID: "part", Regex: `part`}, {ID: "optional", Regex: `optional`},
	}}
	d := mustNew(t, cfg)
	input := credential.Input{RuleID: "key", Secret: " raw-secret\n", Captures: map[string]string{"tenant": "private-tenant"}, Components: map[string]credential.Component{"part": {Secret: "companion-secret", Captures: map[string]string{"region": "private-region"}}}, Attributes: map[string]string{sources.AttrPath: "direct.env", "application": "demo"}}
	result, err := d.AnalyzeCredential(t.Context(), input)
	require.NoError(t, err)
	require.Equal(t, report.ValidationStatusValid, result.Analysis.Status)
	require.Equal(t, report.SeverityMedium, result.Analysis.Severity)
	require.Equal(t, "demo-user", result.Analysis.Identity.Username)
	require.Len(t, result.ComponentSets, 1)
	require.Len(t, result.ComponentSets[0].Components, 1)
	require.Equal(t, result.Analysis, result.ComponentSets[0].Analysis)
	data, err := json.Marshal(result)
	require.NoError(t, err)
	for _, secret := range []string{"raw-secret", "private-tenant", "companion-secret", "private-region"} {
		require.NotContains(t, string(data), secret)
	}
	result.Attributes["application"] = "changed"
	require.Equal(t, "demo", input.Attributes["application"])
	require.Equal(t, "direct.env", input.Attributes[sources.AttrPath])
	require.Equal(t, "private-tenant", input.Captures["tenant"])
	require.Equal(t, "private-region", input.Components["part"].Captures["region"])
	input.Components["optional"] = credential.Component{Secret: "optional-secret"}
	result, err = d.AnalyzeCredential(t.Context(), input)
	require.NoError(t, err)
	require.Len(t, result.ComponentSets[0].Components, 2)
	assert.True(t, result.ComponentSets[0].Components[0].Optional)
}

func TestCredentialRequestBudget(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		limit, requestsPerCall int
		status                 report.ValidationStatus
	}{
		{"one request", 1, 1, report.ValidationStatusNeedsValidation},
		{"two requests", 2, 2, report.ValidationStatusValid},
		{"unlimited", 0, 2, report.ValidationStatusValid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { requests.Add(1); w.WriteHeader(http.StatusOK) }))
			defer server.Close()
			expression := fmt.Sprintf(`let responseOne = http.get(%q, {}); let responseTwo = http.get(%q, {}); {"result":"valid"}`, server.URL+"/first", server.URL+"/second")
			analyzer := mustNew(t, &config.Config{Rules: []config.Rule{{ID: "key", Regex: "key", ValidateExpr: expression}}}, WithMaxRequestsPerTarget(tc.limit))
			for run := 1; run <= 2; run++ {
				result, err := analyzer.AnalyzeCredential(t.Context(), credential.Input{RuleID: "key", Secret: "raw"})
				require.NoError(t, err)
				require.Equal(t, tc.status, result.Analysis.Status)
				require.EqualValues(t, run*tc.requestsPerCall, requests.Load(), "each call gets a fresh request budget")
			}
		})
	}
}

func TestCredentialCancellation(t *testing.T) {
	for _, tc := range []struct {
		name          string
		beforeRequest bool
		wantRequests  int32
	}{
		{"before request", true, 0}, {"during request", false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			started := make(chan struct{})
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { requests.Add(1); close(started); <-r.Context().Done() }))
			defer server.Close()
			analyzer := mustNew(t, &config.Config{Rules: []config.Rule{{ID: "key", Regex: "key", ValidateExpr: fmt.Sprintf(`let r = http.get(%q, {}); {"result":"valid"}`, server.URL)}}})
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			if tc.beforeRequest {
				cancel()
			}
			done := make(chan error, 1)
			go func() {
				_, err := analyzer.AnalyzeCredential(ctx, credential.Input{RuleID: "key", Secret: "raw"})
				done <- err
			}()
			if !tc.beforeRequest {
				select {
				case <-started:
				case <-ctx.Done():
					t.Fatal("request did not start")
				}
				cancel()
			}
			select {
			case err := <-done:
				require.ErrorIs(t, err, context.Canceled)
			case <-time.After(5 * time.Second):
				t.Fatal("validation did not stop")
			}
			require.Equal(t, tc.wantRequests, requests.Load())
		})
	}
}

func TestValidateCredentialMatchesScanAndSupportsConcurrentCalls(t *testing.T) {
	cfg := &config.Config{Rules: []config.Rule{{ID: "key", Regex: `example-key`, ValidateExpr: `{"result":"valid","analysis":{"owner":"demo-user"}}`, AnalyzeExpr: `{"identity":{"username":validation["analysis"]["owner"]},"capabilities":["read"]}`}}}
	d := mustNew(t, cfg)
	scanner, err := scan.New(cfg)
	require.NoError(t, err)
	input := credential.Input{RuleID: "key", Secret: "example-key", Attributes: map[string]string{sources.AttrPath: "example.env"}}
	direct, err := d.AnalyzeCredential(t.Context(), input)
	require.NoError(t, err)
	var scanned report.CredentialReport
	_, err = scanner.Scan(t.Context(), &sources.Reader{Content: strings.NewReader(input.Secret), Attributes: input.Attributes}, func(f report.Finding) error {
		enriched, err := d.Analyze(t.Context(), f)
		if err != nil {
			return err
		}
		scanned = report.NewCredentialReport(enriched, []string{input.Secret})
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, scanned, direct)
	results := make(chan report.CredentialReport, 8)
	failures := make(chan error, 8)
	for range 8 {
		go func() { result, err := d.AnalyzeCredential(t.Context(), input); results <- result; failures <- err }()
	}
	_, err = scanner.Scan(t.Context(), &sources.Reader{Content: strings.NewReader(input.Secret)}, func(report.Finding) error { return nil })
	require.NoError(t, err)
	for range 8 {
		require.NoError(t, <-failures)
		require.Equal(t, direct, <-results)
	}
}

func TestCredentialProviderEnvironment(t *testing.T) {
	const envName = "BETTERLEAKS_TEST_PROVIDER_TOKEN"
	t.Setenv(envName, "permitted")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, r.URL.Query().Get("secret")) }))
	defer server.Close()
	cfg := &config.Config{Rules: []config.Rule{{
		ID: "key", Regex: "key",
		ValidateExpr: fmt.Sprintf(`let access = env.get(%q); let response = http.get(%q + "?secret=" + finding.secret, {});
{"result": access == "permitted" && response.status == 200 ? "valid" : "invalid"}`, envName, server.URL),
		AnalyzeExpr: `{"capabilities":["read"]}`,
	}}}
	for _, tc := range []struct {
		name                   string
		allow, mutateAllowlist bool
		status                 report.ValidationStatus
	}{
		{"denied", false, false, report.ValidationStatusError},
		{"allowed", true, false, report.ValidationStatusValid},
		{"caller changes allowlist", true, true, report.ValidationStatusValid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			names := []string{envName}
			options := []Option{WithDebug(true)}
			if tc.allow {
				options = append(options, WithEnvVars(names...))
			}
			analyzer := mustNew(t, cfg, options...)
			if tc.mutateAllowlist {
				names[0] = "NOT_ALLOWED"
			}
			input := credential.Input{RuleID: "key", Secret: "private-debug-secret"}
			result, err := analyzer.AnalyzeCredential(t.Context(), input)
			require.NoError(t, err)
			require.Equal(t, tc.status, result.Analysis.Status)
			if tc.allow {
				require.NotEmpty(t, result.Analysis.Debug["validation"])
			}
			encoded, err := json.Marshal(result)
			require.NoError(t, err)
			require.NotContains(t, string(encoded), input.Secret)
			if tc.allow {
				require.Contains(t, string(encoded), "[redacted]")
			}
		})
	}
}

func TestRecheckReplacesResultsWithoutMutatingInput(t *testing.T) {
	cfg := &config.Config{Rules: []config.Rule{
		{ID: "key", Regex: `key`, ValidateExpr: `{"result":"invalid"}`, AnalyzeExpr: `{"capabilities":["admin"]}`, Components: []config.Component{{RuleID: "part"}}},
		{ID: "part", Regex: `part`},
	}}
	input := report.Finding{
		RuleID: "key", Match: report.Match{Value: "key"}, Confidence: "high",
		Analysis: report.Analysis{Severity: report.SeverityHigh, Status: report.ValidationStatusValid},
		ComponentSets: []report.ComponentSet{{
			Components: []report.ComponentFinding{{RuleID: "part", Match: report.Match{Value: "companion"}}},
			Analysis:   report.Analysis{Severity: report.SeverityHigh, Status: report.ValidationStatusValid},
		}},
	}
	for _, tc := range []struct {
		name    string
		resolve func(*Analyzer, context.Context, report.Finding) (report.Finding, error)
	}{{"validate", (*Analyzer).Validate}, {"analyze", (*Analyzer).Analyze}} {
		t.Run(tc.name, func(t *testing.T) {
			a := mustNew(t, cfg)
			result, err := tc.resolve(a, t.Context(), input)
			require.NoError(t, err)
			require.Equal(t, "high", result.Confidence)
			require.Equal(t, report.Analysis{Status: report.ValidationStatusInvalid}, result.Analysis)
			require.Equal(t, report.Analysis{Status: report.ValidationStatusInvalid}, result.ComponentSets[0].Analysis)
			require.Equal(t, report.ValidationStatusValid, input.ComponentSets[0].Analysis.Status)
			require.Equal(t, report.SeverityHigh, input.ComponentSets[0].Analysis.Severity)
		})
	}
}

func TestValidateCredentialAfterAnalysis(t *testing.T) {
	for _, tc := range []struct {
		name    string
		options []Option
	}{
		{name: "lazy"}, {name: "precompiled", options: []Option{WithPrecompile()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{Rules: []config.Rule{{ID: "key", Regex: "key", ValidateExpr: `{"result":"valid"}`, AnalyzeExpr: `{"capabilities":["read"]}`}}}
			analyzer := mustNew(t, cfg, tc.options...)
			input := credential.Input{RuleID: "key", Secret: "secret"}
			result, err := analyzer.AnalyzeCredential(t.Context(), input)
			require.NoError(t, err)
			require.Equal(t, report.SeverityMedium, result.Analysis.Severity)
			result, err = analyzer.ValidateCredential(t.Context(), input)
			require.NoError(t, err)
			require.Equal(t, report.Analysis{Status: report.ValidationStatusValid}, result.Analysis)
		})
	}
}

func TestStreamsOwnCachesAndShareRequestBudgets(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { requests.Add(1); w.WriteHeader(http.StatusOK) }))
	defer server.Close()
	cfg := &config.Config{Rules: []config.Rule{{ID: "key", Regex: `key`, ValidateExpr: fmt.Sprintf(`let r = http.get(%q, {}); {"result":"valid"}`, server.URL)}}}
	a := mustNew(t, cfg, WithWorkers(2), WithMaxRequestsPerTarget(1))
	produce := func(ctx context.Context, yield func(report.Finding) error) error {
		for _, secret := range []string{"one", "one", "two"} {
			if err := yield(report.Finding{RuleID: "key", Match: report.Match{Value: secret}}); err != nil {
				return err
			}
		}
		return nil
	}
	for run := 1; run <= 2; run++ {
		statuses := make(map[report.ValidationStatus]int)
		err := a.AnalyzeStream(t.Context(), produce, func(f report.Finding) error { statuses[f.Analysis.Status]++; return nil })
		require.NoError(t, err)
		require.Equal(t, int32(run), requests.Load(), "one shared request budget per stream, fresh next time")
		require.Equal(t, 3, statuses[report.ValidationStatusValid]+statuses[report.ValidationStatusNeedsValidation])
		require.Equal(t, 2, statuses[report.ValidationStatusValid], "duplicates share their completed validation")
		require.Equal(t, 1, statuses[report.ValidationStatusNeedsValidation])
	}
}

func TestMalformedFindingsNeverReachProvider(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(200) }))
	defer server.Close()
	cfg := &config.Config{Rules: []config.Rule{
		{ID: "key", Regex: `(?P<tenant>tenant):(?P<token>token)`, SecretGroup: 2,
			ValidateExpr: fmt.Sprintf(`let r=http.get(%q, {}); {"result": finding.captures.tenant != "" && components.part.captures.region != "" ? "valid" : "invalid"}`, server.URL),
			Components:   []config.Component{{RuleID: "part"}}},
		{ID: "part", Regex: `part`},
	}}
	a, err := New(cfg)
	require.NoError(t, err)
	valid := report.Finding{RuleID: "key", Match: report.Match{Value: "primary-value", Captures: map[string]string{"tenant": "tenant-value"}}, ComponentSets: []report.ComponentSet{{Components: []report.ComponentFinding{{RuleID: "part", Match: report.Match{Value: "part-value", Captures: map[string]string{"region": "region-value"}}}}}}}
	for _, tc := range []struct {
		name   string
		change func(*report.Finding)
		want   string
	}{
		{"unknown rule", func(f *report.Finding) { f.RuleID = "missing" }, "not found"},
		{"empty primary", func(f *report.Finding) { f.Match.Value = "" }, "must not be empty"},
		{"missing primary capture", func(f *report.Finding) { delete(f.Match.Captures, "tenant") }, "missing required capture"},
		{"inconsistent primary capture", func(f *report.Finding) { f.Match.Captures["token"] = "another-value" }, "disagrees"},
		{"no sets", func(f *report.Finding) { f.ComponentSets = nil }, "missing required component"},
		{"empty set", func(f *report.Finding) { f.ComponentSets[0].Components = nil }, "missing required component"},
		{"extra component", func(f *report.Finding) { f.ComponentSets[0].Components[0].RuleID = "extra" }, "not declared"},
		{"duplicate component", func(f *report.Finding) {
			f.ComponentSets[0].Components = append(f.ComponentSets[0].Components, f.ComponentSets[0].Components[0])
		}, "repeats component"},
		{"empty component", func(f *report.Finding) { f.ComponentSets[0].Components[0].Match.Value = "" }, "must not be empty"},
		{"missing component capture", func(f *report.Finding) { f.ComponentSets[0].Components[0].Match.Captures = nil }, "missing required capture"},
		{"oversized input", func(f *report.Finding) { f.ComponentSets = make([]report.ComponentSet, 101) }, "exceed limit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := valid.Clone()
			tc.change(&f)
			_, err := a.Analyze(t.Context(), f)
			require.ErrorContains(t, err, tc.want)
		})
	}
	require.Zero(t, calls.Load())
	result, err := a.Analyze(t.Context(), valid)
	require.NoError(t, err)
	require.Equal(t, report.ValidationStatusValid, result.Analysis.Status)
	require.Equal(t, "primary-value", result.Match.Captures["token"])
	require.NotContains(t, valid.Match.Captures, "token", "canonicalization must not mutate input")
	requirements, err := a.Requirements("key")
	require.NoError(t, err)
	require.Equal(t, []string{"tenant"}, requirements.Captures)
	require.Equal(t, []string{"region"}, requirements.Components[0].Captures)
}

func TestBoundedComponentSearchReportsIncomplete(t *testing.T) {
	for _, tc := range []struct {
		name, working string
		status        report.ValidationStatus
	}{
		{"valid component beyond cap", "part_137", report.ValidationStatusNeedsValidation},
		{"valid component within cap", "part_001", report.ValidationStatusValid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.URL.Path == "/"+tc.working {
					w.WriteHeader(200)
				} else {
					w.WriteHeader(401)
				}
			}))
			defer server.Close()
			cfg := &config.Config{Rules: []config.Rule{{ID: "key", Regex: `PRIMARY`, ValidateExpr: fmt.Sprintf(`let r=http.get(%q+"/"+components.part.secret, {}); {"result":r.status==200 ? "valid" : "invalid"}`, server.URL), Components: []config.Component{{RuleID: "part"}}}, {ID: "part", Regex: `part_[0-9]{3}`, SkipReport: true}}}
			scanner, err := scan.New(cfg)
			require.NoError(t, err)
			var content strings.Builder
			content.WriteString("PRIMARY\n")
			for i := 1; i <= 137; i++ {
				fmt.Fprintf(&content, "part_%03d\n", i)
			}
			findings := scanner.ScanString(content.String())
			require.Len(t, findings, 1)
			require.Len(t, findings[0].ComponentSets, 100)
			require.True(t, findings[0].ComponentSetsTruncated)
			wire, err := json.Marshal(findings[0])
			require.NoError(t, err)
			var restored report.Finding
			require.NoError(t, json.Unmarshal(wire, &restored))
			require.True(t, restored.ComponentSetsTruncated)
			a, err := New(cfg)
			require.NoError(t, err)
			resolved, err := a.Analyze(t.Context(), restored)
			require.NoError(t, err)
			require.EqualValues(t, 100, calls.Load(), "never probe beyond the cap")
			require.True(t, resolved.ComponentSetsTruncated)
			require.Equal(t, tc.status, resolved.Analysis.Status)
			if tc.status == report.ValidationStatusNeedsValidation {
				for _, set := range resolved.ComponentSets {
					require.Equal(t, report.ValidationStatusInvalid, set.Analysis.Status)
				}
			}
		})
	}
}

func TestCredentialDedupIgnoresOccurrence(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(200) }))
	defer server.Close()
	cfg := &config.Config{Rules: []config.Rule{{ID: "key", Regex: `TOKEN`, ValidateExpr: fmt.Sprintf(`let r=http.get(%q, {}); {"result":r.status==200 ? "valid" : "invalid"}`, server.URL)}}}
	a, err := New(cfg, WithWorkers(8))
	require.NoError(t, err)
	count := 0
	err = a.AnalyzeStream(t.Context(), func(ctx context.Context, yield func(report.Finding) error) error {
		for i := 0; i < 30; i++ {
			f := report.Finding{RuleID: "key", Match: report.Match{Full: fmt.Sprintf("match%d TOKEN", i), Value: "TOKEN"}, Location: report.Location{Path: fmt.Sprintf("file%d.env", i)}, Line: fmt.Sprint(i), MatchContext: fmt.Sprint(i), Attributes: map[string]string{"git.message": fmt.Sprint(i)}}
			if err := yield(f); err != nil {
				return err
			}
		}
		return nil
	}, func(f report.Finding) error {
		count++
		require.Equal(t, report.ValidationStatusValid, f.Analysis.Status)
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, 30, count)
	require.EqualValues(t, 1, calls.Load())
}

func TestProducerOwnsInputAfterYield(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-release; w.WriteHeader(200) }))
	defer server.Close()
	cfg := &config.Config{Rules: []config.Rule{{ID: "key", Regex: `TOKEN`, ValidateExpr: fmt.Sprintf(`let r=http.get(%q, {}); {"result": finding.captures.tenant=="before" && components.part.captures.region=="before" ? "valid" : "invalid"}`, server.URL), Components: []config.Component{{RuleID: "part"}}}, {ID: "part", Regex: `PART`}}}
	a, err := New(cfg)
	require.NoError(t, err)
	f := report.Finding{RuleID: "key", Match: report.Match{Value: "TOKEN", Captures: map[string]string{"tenant": "before"}}, Attributes: map[string]string{"application": "before"}, Tags: []string{"before"}, ComponentSets: []report.ComponentSet{{Components: []report.ComponentFinding{{RuleID: "part", Match: report.Match{Value: "PART", Captures: map[string]string{"region": "before"}}}}}}}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var got report.Finding
	err = a.AnalyzeStream(ctx, func(ctx context.Context, yield func(report.Finding) error) error {
		defer close(release)
		if err := yield(f); err != nil {
			return err
		}
		select {
		case <-started:
		case <-ctx.Done():
			return ctx.Err()
		}
		f.Match.Captures["tenant"] = "after"
		f.Attributes["application"] = "after"
		f.Tags[0] = "after"
		f.ComponentSets[0].Components[0].Match.Captures["region"] = "after"
		f.ComponentSets[0].Components[0].Match.Value = "AFTER"
		return nil
	}, func(f report.Finding) error { got = f; return nil })
	require.NoError(t, err)
	require.Equal(t, report.ValidationStatusValid, got.Analysis.Status)
	require.Equal(t, "before", got.Attributes["application"])
	require.Equal(t, []string{"before"}, got.Tags)
	require.Equal(t, "PART", got.ComponentSets[0].Components[0].Match.Value)
}

func TestOptionalCaptures(t *testing.T) {
	cfg := &config.Config{Rules: []config.Rule{{ID: "key", Regex: "TOKEN", ValidateExpr: `{"result": (finding.captures.region ?? "default") == "default" ? "valid" : "invalid"}`}}}
	analyzer := mustNew(t, cfg)
	requirements, err := analyzer.Requirements("key")
	require.NoError(t, err)
	require.Empty(t, requirements.Captures)
	for _, tc := range []struct {
		name     string
		captures map[string]string
		status   report.ValidationStatus
	}{
		{"omitted", nil, report.ValidationStatusValid},
		{"supplied default", map[string]string{"region": "default"}, report.ValidationStatusValid},
		{"supplied other region", map[string]string{"region": "other"}, report.ValidationStatusInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := analyzer.ValidateCredential(t.Context(), credential.Input{RuleID: "key", Secret: "TOKEN", Captures: tc.captures})
			require.NoError(t, err)
			require.Equal(t, tc.status, result.Analysis.Status)
		})
	}
}
