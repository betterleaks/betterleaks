package validate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/detect"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/sources"
)

func mustNewValidator(t *testing.T, cfg *config.Config, options Options) *Validator {
	t.Helper()
	validator, err := NewValidator(cfg, options)
	require.NoError(t, err)
	return validator
}

func TestValidateCredentialPipeline(t *testing.T) {
	for _, tc := range []struct {
		name, validation, analysis string
		enabled                    bool
		status                     report.ValidationStatus
		severity                   report.Severity
	}{
		{"validation only", `{"result":"valid"}`, `invalid syntax ???`, false, report.ValidationStatusValid, report.SeverityNone},
		{"analysis", `{"result":"valid","analysis":{"owner":"demo-user"}}`, `{"identity":{"username":validation["analysis"]["owner"]},"capabilities":["write"]}`, true, report.ValidationStatusValid, report.SeverityHigh},
		{"no analyzer", `{"result":"valid"}`, ``, true, report.ValidationStatusValid, report.SeverityNone},
		{"empty analysis", `{"result":"valid"}`, `{}`, true, report.ValidationStatusValid, report.SeverityUnknown},
		{"invalid skips analysis", `{"result":"invalid"}`, `{"capabilities":["admin"]}`, true, report.ValidationStatusInvalid, report.SeverityNone},
		{"revoked", `{"result":"revoked"}`, `{}`, true, report.ValidationStatusRevoked, report.SeverityNone},
		{"malformed validation", `{"result":123}`, `{}`, true, report.ValidationStatusError, report.SeverityNone},
		{"analysis failure preserves validation", `{"result":"valid"}`, `{"capabilities":123}`, true, report.ValidationStatusValid, report.SeverityUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{Prefilter: "true", Filter: "true", Rules: []config.Rule{{
				ID: "credential", Regex: `never-matches-this-input`, Confidence: "low", SkipReport: true,
				ValidateExpr: tc.validation, AnalyzeExpr: tc.analysis,
			}}}
			d := mustNewValidator(t, cfg, Options{Analysis: tc.enabled})
			result, err := d.ValidateCredential(t.Context(), Credential{RuleID: "credential", Secret: "raw-secret"})
			require.NoError(t, err)
			assert.Equal(t, tc.status, result.Validation.Status)
			assert.Equal(t, tc.severity, result.Analysis.Severity)
			if tc.name == "analysis" {
				require.NotNil(t, result.Analysis.Identity)
				assert.Equal(t, "demo-user", result.Analysis.Identity.Username)
			}
			if tc.name == "analysis failure preserves validation" {
				assert.NotEmpty(t, result.Analysis.Reason)
			}
		})
	}
}

func TestValidateCredentialInputs(t *testing.T) {
	cfg := &config.Config{Rules: []config.Rule{
		{ID: "primary", Regex: `(?P<tenant>tenant)-(?P<secret>key)`, SecretGroup: 2, ValidateExpr: `{"result":"valid"}`, AnalyzeExpr: `{"identity":{"id":finding.captures["tenant"]}}`, Components: []*config.Component{{RuleID: "part"}, {RuleID: "optional", Optional: true}}},
		{ID: "part", Regex: `part`}, {ID: "optional", Regex: `optional`},
	}}
	d := mustNewValidator(t, cfg, Options{Analysis: true})
	for _, tc := range []struct {
		name  string
		input Credential
		want  string
	}{
		{"unknown rule", Credential{RuleID: "missing", Secret: "key"}, "not found"},
		{"no validator", Credential{RuleID: "part", Secret: "key"}, "does not define validation"},
		{"empty secret", Credential{RuleID: "primary"}, "must not be empty"},
		{"large secret", Credential{RuleID: "primary", Secret: strings.Repeat("s", (1<<20)+1)}, "exceeds"},
		{"analysis capture missing", Credential{RuleID: "primary", Secret: "key"}, "missing required capture(s)"},
		{"component missing", Credential{RuleID: "primary", Secret: "key", Captures: map[string]string{"tenant": "demo"}}, "missing required component(s): part"},
		{"extra component", Credential{RuleID: "primary", Secret: "key", Captures: map[string]string{"tenant": "demo"}, Components: map[string]CredentialComponent{"part": {Secret: "x"}, "extra": {Secret: "y"}}}, "not declared"},
		{"empty component", Credential{RuleID: "primary", Secret: "key", Captures: map[string]string{"tenant": "demo"}, Components: map[string]CredentialComponent{"part": {}}}, "must not be empty"},
		{"empty capture name", Credential{RuleID: "primary", Secret: "key", Captures: map[string]string{"": "value"}}, "capture name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := d.ValidateCredential(t.Context(), tc.input)
			require.ErrorContains(t, err, tc.want)
		})
	}
	_, err := (*Validator)(nil).ValidateCredential(t.Context(), Credential{RuleID: "primary", Secret: "key"})
	require.ErrorContains(t, err, "must be constructed")
	for _, expression := range []struct{ validation, analysis string }{{`???`, ``}, {`{"result":"valid"}`, `???`}} {
		bad := mustNewValidator(t, &config.Config{Rules: []config.Rule{{ID: "bad", Regex: `bad`, ValidateExpr: expression.validation, AnalyzeExpr: expression.analysis}}}, Options{Analysis: true})
		_, err := bad.ValidateCredential(t.Context(), Credential{RuleID: "bad", Secret: "x"})
		require.ErrorContains(t, err, "compiling rule bad")
	}
}

func TestValidateCredentialComponentsAndRedaction(t *testing.T) {
	cfg := &config.Config{Rules: []config.Rule{
		{ID: "key", Regex: `key`, ValidateExpr: `finding["secret"] == " raw-secret\n" && finding.captures["tenant"] == "private-tenant" && components["part"].secret == "companion-secret" && components["part"].captures["region"] == "private-region" && attributes["path"] == "direct.env" ? {"result":"valid", "reason":finding["secret"], "echo":components["part"].captures["region"], "analysis":{"owner":"demo-user"}} : {"result":"invalid"}`,
			AnalyzeExpr: `{"identity":{"username":validation["analysis"]["owner"]},"capabilities":["read"],"metadata":{"echo":finding.captures["tenant"]+components["part"].secret}}`,
			Components:  []*config.Component{{RuleID: "part"}, {RuleID: "optional", Optional: true}}},
		{ID: "part", Regex: `part`}, {ID: "optional", Regex: `optional`},
	}}
	d := mustNewValidator(t, cfg, Options{Analysis: true})
	input := Credential{RuleID: "key", Secret: " raw-secret\n", Captures: map[string]string{"tenant": "private-tenant"}, Components: map[string]CredentialComponent{"part": {Secret: "companion-secret", Captures: map[string]string{"region": "private-region"}}}, Attributes: map[string]string{sources.AttrPath: "direct.env"}}
	result, err := d.ValidateCredential(t.Context(), input)
	require.NoError(t, err)
	require.Equal(t, report.ValidationStatusValid, result.Validation.Status)
	require.Equal(t, report.SeverityMedium, result.Analysis.Severity)
	require.Equal(t, "demo-user", result.Analysis.Identity.Username)
	require.Len(t, result.Validation.ComponentSets, 1)
	require.Len(t, result.Validation.ComponentSets[0].Components, 1)
	require.Equal(t, result.Analysis, result.Validation.ComponentSets[0].Analysis)
	data, err := json.Marshal(result)
	require.NoError(t, err)
	for _, secret := range []string{"raw-secret", "private-tenant", "companion-secret", "private-region"} {
		require.NotContains(t, string(data), secret)
	}
	result.Attributes[sources.AttrPath] = "changed"
	require.Equal(t, "direct.env", input.Attributes[sources.AttrPath])
	require.Equal(t, "private-tenant", input.Captures["tenant"])
	require.Equal(t, "private-region", input.Components["part"].Captures["region"])
	input.Components["optional"] = CredentialComponent{Secret: "optional-secret"}
	result, err = d.ValidateCredential(t.Context(), input)
	require.NoError(t, err)
	require.Len(t, result.Validation.ComponentSets[0].Components, 2)
	assert.True(t, result.Validation.ComponentSets[0].Components[0].Optional)
}

func TestValidateCredentialProviderLimitsAndCancellation(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); fmt.Fprint(w, `{"owner":"demo-user"}`) }))
	defer server.Close()
	expression := fmt.Sprintf(`let responseOne = http.get(%q, {}); let responseTwo = http.get(%q, {}); {"result":"valid"}`, server.URL+"/first", server.URL+"/second")
	d := mustNewValidator(t, &config.Config{Rules: []config.Rule{{ID: "key", Regex: `key`, ValidateExpr: expression}}}, Options{Analysis: true, MaxRequestsPerTarget: 1})
	for range 2 {
		result, err := d.ValidateCredential(t.Context(), Credential{RuleID: "key", Secret: "raw"})
		require.NoError(t, err)
		require.Equal(t, report.ValidationStatusNeedsValidation, result.Validation.Status)
	}
	require.Equal(t, int32(2), requests.Load(), "each call gets a fresh request budget")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := d.ValidateCredential(ctx, Credential{RuleID: "key", Secret: "raw"})
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, int32(2), requests.Load())
	started := make(chan struct{})
	blocked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done() }))
	defer blocked.Close()
	d = mustNewValidator(t, &config.Config{Rules: []config.Rule{{ID: "blocked", Regex: `x`, ValidateExpr: fmt.Sprintf(`let r = http.get(%q, {}); {"result":"valid"}`, blocked.URL)}}}, Options{})
	ctx, cancel = context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := d.ValidateCredential(ctx, Credential{RuleID: "blocked", Secret: "raw"}); done <- err }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("request did not start")
	}
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("validation did not stop")
	}
}

func TestValidateCredentialMatchesScanAndSupportsConcurrentCalls(t *testing.T) {
	cfg := &config.Config{Rules: []config.Rule{{ID: "key", Regex: `example-key`, ValidateExpr: `{"result":"valid","analysis":{"owner":"demo-user"}}`, AnalyzeExpr: `{"identity":{"username":validation["analysis"]["owner"]},"capabilities":["read"]}`}}}
	d := mustNewValidator(t, cfg, Options{Analysis: true})
	detector, err := detect.NewDetector(cfg, detect.WithAnalysis(detect.ProviderOptions{}))
	require.NoError(t, err)
	input := Credential{RuleID: "key", Secret: "example-key", Attributes: map[string]string{sources.AttrPath: "example.env"}}
	direct, err := d.ValidateCredential(t.Context(), input)
	require.NoError(t, err)
	var scanned report.CredentialReport
	_, err = detector.Scan(t.Context(), &sources.Reader{Content: strings.NewReader(input.Secret), Attributes: input.Attributes}, func(f report.Finding) error {
		scanned = report.NewCredentialReport(f, []string{input.Secret})
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, scanned, direct)
	results := make(chan report.CredentialReport, 8)
	failures := make(chan error, 8)
	for range 8 {
		go func() { result, err := d.ValidateCredential(t.Context(), input); results <- result; failures <- err }()
	}
	_, err = detector.Scan(t.Context(), &sources.Reader{Content: strings.NewReader(input.Secret)}, func(report.Finding) error { return nil })
	require.NoError(t, err)
	for range 8 {
		require.NoError(t, <-failures)
		require.Equal(t, direct, <-results)
	}
}

func TestValidateCredentialProviderEnvironmentAndDebug(t *testing.T) {
	t.Setenv("BETTERLEAKS_DIRECT_TEST", "permitted")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, r.URL.Query().Get("secret"))
	}))
	defer server.Close()
	cfg := &config.Config{Rules: []config.Rule{{
		ID: "key", Regex: `key`,
		ValidateExpr: fmt.Sprintf(`let access = env.get("BETTERLEAKS_DIRECT_TEST");
let response = http.get(%q + "?secret=" + finding["secret"], {});
{"result": access == "permitted" && response.status == 200 ? "valid" : "invalid"}`, server.URL),
		AnalyzeExpr: `{"capabilities": ["read"]}`,
	}}}
	input := Credential{RuleID: "key", Secret: "private-debug-secret"}
	denied := mustNewValidator(t, cfg, Options{Analysis: true, Debug: true})
	result, err := denied.ValidateCredential(t.Context(), input)
	require.NoError(t, err)
	require.Equal(t, report.ValidationStatusError, result.Validation.Status)
	allowed := mustNewValidator(t, cfg, Options{Analysis: true, Debug: true, EnvVars: []string{"BETTERLEAKS_DIRECT_TEST"}})
	result, err = allowed.ValidateCredential(t.Context(), input)
	require.NoError(t, err)
	require.Equal(t, report.ValidationStatusValid, result.Validation.Status)
	require.NotEmpty(t, result.Validation.Metadata, "debug metadata should be present")
	encoded, err := json.Marshal(result)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), input.Secret)
	require.Contains(t, string(encoded), "[redacted]")
}
