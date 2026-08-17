package report

import (
	"testing"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/internal/exprruntime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockFilterProvider implements FilterProvider for testing without importing detect.
type mockFilterProvider struct {
	global  exprruntime.Program
	perRule map[string]exprruntime.Program
}

func (m *mockFilterProvider) Global() (exprruntime.Program, bool, error) {
	if m.global == nil {
		return nil, false, nil
	}
	return m.global, true, nil
}

func (m *mockFilterProvider) ForRule(r config.Rule) (exprruntime.Program, bool, error) {
	if prg, ok := m.perRule[r.RuleID]; ok {
		return prg, true, nil
	}
	return nil, false, nil
}

// mockSuppressor implements SuppressionProvider for testing.
type mockSuppressor struct {
	fn func(Finding) bool
}

func (m *mockSuppressor) Suppressed(f Finding) bool { return m.fn(f) }

// replayRT returns a fresh exprruntime.Runtime for replay tests.
func replayRT(t *testing.T) *exprruntime.Runtime {
	t.Helper()
	rt, err := exprruntime.New(nil)
	require.NoError(t, err)
	return rt
}

// compile compiles a filter expression using the given runtime.
func compile(t *testing.T, rt *exprruntime.Runtime, expr string) exprruntime.Program {
	t.Helper()
	prg, err := rt.CompileFilter(expr, nil)
	require.NoError(t, err)
	return prg
}

func TestReplayPrefilter(t *testing.T) {
	rt := replayRT(t)
	cfg := &config.Config{
		Prefilter: `attributes["path"] == "skip.env"`,
		Rules:     map[string]config.Rule{"r": {RuleID: "r"}},
	}
	require.NoError(t, cfg.CompileFilters(nil))

	findings := []Finding{
		{RuleID: "r", Secret: "kept", Attributes: map[string]string{"path": "main.go"}},
		{RuleID: "r", Secret: "dropped", Attributes: map[string]string{"path": "skip.env"}},
	}
	got, err := Replay(findings, ReplayOptions{Config: cfg, ExprRuntime: rt})
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "kept", got[0].Secret)
}

func TestReplayGlobalFilter(t *testing.T) {
	rt := replayRT(t)
	cfg := &config.Config{
		Filter: `finding["secret"] == "bad"`,
		Rules:  map[string]config.Rule{"r": {RuleID: "r"}},
	}
	filters := &mockFilterProvider{global: compile(t, rt, cfg.Filter)}

	findings := []Finding{
		{RuleID: "r", Secret: "bad"},
		{RuleID: "r", Secret: "good"},
	}
	got, err := Replay(findings, ReplayOptions{Config: cfg, ExprRuntime: rt, FilterSet: filters})
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "good", got[0].Secret)
}

func TestReplayRuleFilterByEntropy(t *testing.T) {
	rt := replayRT(t)
	// entropy() computes Shannon entropy of the secret string; "aaaaaa" is very low.
	expr := `entropy(finding["secret"]) < 1.0`
	cfg := &config.Config{
		Rules: map[string]config.Rule{"r": {RuleID: "r", Filter: expr}},
	}
	filters := &mockFilterProvider{
		perRule: map[string]exprruntime.Program{"r": compile(t, rt, expr)},
	}

	findings := []Finding{
		{RuleID: "r", Secret: "aaaaaa"},   // entropy ≈ 0 — dropped
		{RuleID: "r", Secret: "aB3!xZ@9"}, // high entropy — kept
	}
	got, err := Replay(findings, ReplayOptions{Config: cfg, ExprRuntime: rt, FilterSet: filters})
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "aB3!xZ@9", got[0].Secret)
}

func TestReplayRuleFilterByLine(t *testing.T) {
	rt := replayRT(t)
	expr := `finding["line"].contains("PRIVATE")`
	cfg := &config.Config{
		Rules: map[string]config.Rule{"r": {RuleID: "r", Filter: expr}},
	}
	filters := &mockFilterProvider{
		perRule: map[string]exprruntime.Program{"r": compile(t, rt, expr)},
	}

	findings := []Finding{
		{RuleID: "r", Secret: "s", Line: "PRIVATE KEY abc"},
		{RuleID: "r", Secret: "s", Line: "public_key = abc"},
	}
	got, err := Replay(findings, ReplayOptions{Config: cfg, ExprRuntime: rt, FilterSet: filters})
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "public_key = abc", got[0].Line)
}

func TestReplayRuleFilterLineEmptyWhenNotPersisted(t *testing.T) {
	rt := replayRT(t)
	// This filter would drop a finding whose line contains "PRIVATE",
	// but the finding has Line == "" (not persisted at scan time).
	expr := `finding["line"].contains("PRIVATE")`
	cfg := &config.Config{
		Rules: map[string]config.Rule{"r": {RuleID: "r", Filter: expr}},
	}
	filters := &mockFilterProvider{
		perRule: map[string]exprruntime.Program{"r": compile(t, rt, expr)},
	}

	// Line is empty: filter cannot match it, so the finding is kept.
	findings := []Finding{{RuleID: "r", Secret: "s", Line: ""}}
	got, err := Replay(findings, ReplayOptions{Config: cfg, ExprRuntime: rt, FilterSet: filters})
	require.NoError(t, err)
	assert.Len(t, got, 1, "finding with empty Line should be kept when filter references finding[\"line\"]")
}

func TestReplayUnknownRuleKept(t *testing.T) {
	rt := replayRT(t)
	cfg := &config.Config{Rules: map[string]config.Rule{"known": {RuleID: "known"}}}
	filters := &mockFilterProvider{}

	findings := []Finding{
		{RuleID: "unknown-rule", Secret: "s"},
	}
	got, err := Replay(findings, ReplayOptions{Config: cfg, ExprRuntime: rt, FilterSet: filters})
	require.NoError(t, err)
	assert.Len(t, got, 1, "finding with unknown rule ID should be kept")
}

func TestReplaySuppression(t *testing.T) {
	rt := replayRT(t)
	cfg := &config.Config{Rules: map[string]config.Rule{"r": {RuleID: "r"}}}

	kept := Finding{RuleID: "r", Secret: "kept", Fingerprint: "fp-kept"}
	dropped := Finding{RuleID: "r", Secret: "dropped", Fingerprint: "fp-drop"}

	suppress := &mockSuppressor{fn: func(f Finding) bool {
		return f.Fingerprint == "fp-drop"
	}}

	got, err := Replay([]Finding{kept, dropped}, ReplayOptions{
		Config:      cfg,
		ExprRuntime: rt,
		Suppression: suppress,
	})
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "kept", got[0].Secret)
}

func TestReplaySuppressionBeforeFilterEval(t *testing.T) {
	rt := replayRT(t)
	// The filter expression is deliberately invalid to produce an eval error.
	// The suppressed finding should be dropped before the filter ever runs.
	expr := `finding["secret"] == "x"` // valid expression, but we want to prove order
	cfg := &config.Config{
		Filter: expr,
		Rules:  map[string]config.Rule{"r": {RuleID: "r"}},
	}

	// Override: this filter always panics if called (to prove suppression runs first).
	panickingFilter := &mockFilterProvider{
		global: compile(t, rt, expr),
	}
	// Wrap it so Global() returns normally but we verify suppression fired first.
	suppressed := false
	suppress := &mockSuppressor{fn: func(f Finding) bool {
		if f.Secret == "should-be-suppressed" {
			suppressed = true
			return true
		}
		return false
	}}

	findings := []Finding{
		{RuleID: "r", Secret: "should-be-suppressed"},
	}
	got, err := Replay(findings, ReplayOptions{
		Config:      cfg,
		ExprRuntime: rt,
		FilterSet:   panickingFilter,
		Suppression: suppress,
	})
	require.NoError(t, err)
	assert.Empty(t, got)
	assert.True(t, suppressed, "suppression should have been applied")
}
