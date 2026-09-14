package analyze

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/stretchr/testify/require"
)

func TestRecheckReplacesResultsWithoutMutatingInput(t *testing.T) {
	cfg := &config.Config{Rules: []config.Rule{
		{ID: "key", Regex: `key`, ValidateExpr: `{"result":"invalid"}`, AnalyzeExpr: `{"capabilities":["admin"]}`, Components: []*config.Component{{RuleID: "part"}}},
		{ID: "part", Regex: `part`},
	}}
	a := mustNew(t, cfg)
	input := report.Finding{
		RuleID: "key", Secret: "key", Confidence: "high",
		Validation: report.Validation{Status: report.ValidationStatusValid},
		Analysis:   report.Analysis{Severity: report.SeverityHigh},
		ComponentSets: []report.ComponentSet{{
			Components: []*report.ComponentFinding{{RuleID: "part", Secret: "companion"}},
			Validation: report.Validation{Status: report.ValidationStatusValid},
			Analysis:   report.Analysis{Severity: report.SeverityHigh},
		}},
	}
	for _, resolve := range []func(context.Context, report.Finding) (report.Finding, error){a.Validate, a.Analyze} {
		result, err := resolve(t.Context(), input)
		require.NoError(t, err)
		require.Equal(t, "high", result.Confidence)
		require.Equal(t, report.ValidationStatusInvalid, result.Validation.Status)
		require.True(t, result.Analysis.IsZero())
		require.Equal(t, report.ValidationStatusInvalid, result.ComponentSets[0].Validation.Status)
		require.True(t, result.ComponentSets[0].Analysis.IsZero())
		require.Equal(t, report.ValidationStatusValid, input.ComponentSets[0].Validation.Status)
		require.Equal(t, report.SeverityHigh, input.ComponentSets[0].Analysis.Severity)
	}
}

func TestValidationOnlyAfterAnalysis(t *testing.T) {
	cfg := &config.Config{Rules: []config.Rule{{ID: "key", Regex: `key`, ValidateExpr: `{"result":"valid"}`, AnalyzeExpr: `{"capabilities":["read"]}`}}}
	a := mustNew(t, cfg, WithPrecompile())
	input := Credential{RuleID: "key", Secret: "secret"}
	result, err := a.AnalyzeCredential(t.Context(), input)
	require.NoError(t, err)
	require.Equal(t, report.SeverityMedium, result.Analysis.Severity)
	result, err = a.ValidateCredential(t.Context(), input)
	require.NoError(t, err)
	require.True(t, result.Analysis.IsZero())
	cfg.Rules[0].AnalyzeExpr = `invalid syntax ???`
	_, err = New(cfg, WithPrecompile())
	require.ErrorContains(t, err, "analysis")
}

func TestStreamsOwnCachesAndShareRequestBudgets(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { requests.Add(1); w.WriteHeader(http.StatusOK) }))
	defer server.Close()
	cfg := &config.Config{Rules: []config.Rule{{ID: "key", Regex: `key`, ValidateExpr: fmt.Sprintf(`let r = http.get(%q, {}); {"result":"valid"}`, server.URL)}}}
	a := mustNew(t, cfg, WithWorkers(2), WithMaxRequestsPerTarget(1))
	produce := func(ctx context.Context, yield func(report.Finding) error) error {
		for _, secret := range []string{"one", "one", "two"} {
			if err := yield(report.Finding{RuleID: "key", Secret: secret}); err != nil {
				return err
			}
		}
		return nil
	}
	for run := 1; run <= 2; run++ {
		statuses := make(map[report.ValidationStatus]int)
		err := a.AnalyzeStream(t.Context(), produce, func(f report.Finding) error { statuses[f.Validation.Status]++; return nil })
		require.NoError(t, err)
		require.Equal(t, int32(run), requests.Load(), "one shared request budget per stream, fresh next time")
		require.Equal(t, 3, statuses[report.ValidationStatusValid]+statuses[report.ValidationStatusNeedsValidation])
		require.Equal(t, 2, statuses[report.ValidationStatusValid], "duplicates share their completed validation")
		require.Equal(t, 1, statuses[report.ValidationStatusNeedsValidation])
	}
}
