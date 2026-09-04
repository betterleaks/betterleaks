package validate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/v2/internal/exprruntime"
	"github.com/betterleaks/betterleaks/v2/report"
)

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
		Secret: "secret-value",
		Match:  "secret-value",
	}
	require.NoError(t, pool.SubmitWithAnalysisContext(t.Context(), finding, validationProgram, analysisProgram))
	require.NoError(t, pool.SubmitWithAnalysisContext(t.Context(), finding, validationProgram, analysisProgram))
	pool.Close()

	for range 2 {
		result := <-results
		assert.Equal(t, report.ValidationStatusValid, result.Validation.Status)
		assert.Empty(t, result.Validation.Metadata)
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
		Secret: "secret-value",
	}, validationProgram, analysisProgram))
	pool.Close()

	result := <-results
	assert.Equal(t, report.ValidationStatusInvalid, result.Validation.Status)
	assert.True(t, result.Analysis.IsZero())
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
		Secret: "secret-value",
	}
	require.NoError(t, pool.SubmitWithAnalysisContext(t.Context(), finding, validationProgram, analysisProgram))
	require.NoError(t, pool.SubmitWithAnalysisContext(t.Context(), finding, validationProgram, analysisProgram))
	pool.Close()

	for range 2 {
		result := <-results
		assert.Equal(t, report.ValidationStatusValid, result.Validation.Status)
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
		Secret: "primary-secret",
		ComponentSets: []report.ComponentSet{{Components: []*report.ComponentFinding{{
			RuleID: "account",
			Secret: "account-secret",
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
