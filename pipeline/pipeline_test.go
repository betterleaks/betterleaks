package pipeline

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/betterleaks/betterleaks/v2/analyze"
	"github.com/betterleaks/betterleaks/v2/config"
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

func TestCanonicalCapturesAcrossCredentialStages(t *testing.T) {
	cfg := &config.Config{Rules: []config.Rule{
		{
			ID: "primary", Regex: `(?P<tenant>acme):(?P<key>primary)`, SecretGroup: 2,
			// Inspect this match's captures before any companion is assembled.
			Filter:     `finding.captures.tenant != "acme"`,
			Components: []*config.Component{{RuleID: "part"}, {RuleID: "optional", Optional: true}},
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
		direct, err := validator.AnalyzeCredential(t.Context(), analyze.Credential{
			RuleID: "primary", Secret: "primary", Captures: map[string]string{"tenant": "acme"},
			Components: map[string]analyze.CredentialComponent{
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

func TestSummarySeparatesDetectedAndEmitted(t *testing.T) {
	cfg := &config.Config{Rules: []config.Rule{{ID: "key", Regex: `TOKEN`}}}
	scanner, err := scan.New(cfg)
	require.NoError(t, err)
	analyzer, err := analyze.New(cfg)
	require.NoError(t, err)
	p, err := New(scanner, analyzer, WithValidationStatuses(report.ValidationStatusValid))
	require.NoError(t, err)
	summary, err := p.Scan(t.Context(), &sources.Reader{Content: strings.NewReader("TOKEN")}, func(f report.Finding) error { t.Fatal("unchecked result passed valid filter"); return nil })
	require.NoError(t, err)
	require.Equal(t, 1, summary.DetectedFindings)
	require.Zero(t, summary.EmittedFindings)
	require.Equal(t, map[report.ValidationStatus]int{report.ValidationStatusNone: 1}, summary.ValidationCounts)
}
