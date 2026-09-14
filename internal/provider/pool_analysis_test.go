package provider

import (
	"encoding/json"
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
		ComponentSets: []report.ComponentSet{{Components: []*report.ComponentFinding{{
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
 {"result": label == "invalid" ? "invalid" : "valid", "reason": "accepted " + label,
 "tenant": label, "shared": "from validation", "analysis": {"owner":label, "private":"unexported-evidence"}}
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
		finding.ComponentSets = append(finding.ComponentSets, report.ComponentSet{Components: []*report.ComponentFinding{{RuleID: "account", Match: report.Match{Value: "credential-" + label, Captures: map[string]string{"label": label}}}}})
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
	require.Equal(t, "admin", first.Analysis.Identity.Username)
	require.Equal(t, "accepted admin; permissions for admin", first.Analysis.Reason)
	require.Equal(t, map[string]any{"tenant": "admin", "shared": "from analysis", "permissions_for": "admin"}, first.Analysis.Metadata)
	require.Equal(t, first.ComponentSets[1].Analysis, first.Analysis)
	encoded, err := json.Marshal(first)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "unexported-evidence")
	require.True(t, finding.Analysis.IsZero())
	require.True(t, finding.ComponentSets[0].Analysis.IsZero())
	first.Analysis.Metadata["tenant"] = "changed"
	first.Analysis.Identity.Username = "changed"
	first.Analysis.Capabilities[0] = report.CapabilityRead
	require.Equal(t, "admin", second.Analysis.Metadata["tenant"])
	require.Equal(t, "admin", second.Analysis.Identity.Username)
	require.Equal(t, []report.Capability{report.CapabilityAdmin}, second.Analysis.Capabilities)
}
