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

func TestReplay(t *testing.T) {
	rt, err := exprruntime.New(nil)
	require.NoError(t, err)

	compile := func(expr string) exprruntime.Program {
		prg, err := rt.CompileFilter(expr, nil)
		require.NoError(t, err)
		return prg
	}

	tests := []struct {
		name      string
		cfg       *config.Config
		filters   FilterProvider
		suppress  SuppressionProvider
		findings  []Finding
		wantCount int
		check     func(*testing.T, []Finding)
	}{
		{
			name: "prefilter drops by path",
			cfg: &config.Config{
				Prefilter: `attributes["path"] == "skip.env"`,
				Rules:     map[string]config.Rule{"r": {RuleID: "r"}},
			},
			findings: []Finding{
				{RuleID: "r", Secret: "kept", Attributes: map[string]string{"path": "main.go"}},
				{RuleID: "r", Secret: "dropped", Attributes: map[string]string{"path": "skip.env"}},
			},
			wantCount: 1,
			check: func(t *testing.T, got []Finding) {
				assert.Equal(t, "kept", got[0].Secret)
			},
		},
		{
			name: "global filter drops by secret",
			cfg: &config.Config{
				Filter: `finding["secret"] == "bad"`,
				Rules:  map[string]config.Rule{"r": {RuleID: "r"}},
			},
			filters: &mockFilterProvider{global: compile(`finding["secret"] == "bad"`)},
			findings: []Finding{
				{RuleID: "r", Secret: "bad"},
				{RuleID: "r", Secret: "good"},
			},
			wantCount: 1,
			check: func(t *testing.T, got []Finding) {
				assert.Equal(t, "good", got[0].Secret)
			},
		},
		{
			name: "per-rule filter drops by entropy",
			cfg: &config.Config{
				// entropy() computes Shannon entropy; "aaaaaa" is very low.
				Rules: map[string]config.Rule{"r": {RuleID: "r", Filter: `entropy(finding["secret"]) < 1.0`}},
			},
			filters: &mockFilterProvider{
				perRule: map[string]exprruntime.Program{"r": compile(`entropy(finding["secret"]) < 1.0`)},
			},
			findings: []Finding{
				{RuleID: "r", Secret: "aaaaaa"},   // entropy ≈ 0 — dropped
				{RuleID: "r", Secret: "aB3!xZ@9"}, // high entropy — kept
			},
			wantCount: 1,
			check: func(t *testing.T, got []Finding) {
				assert.Equal(t, "aB3!xZ@9", got[0].Secret)
			},
		},
		{
			name: "per-rule filter drops by line when Line is set",
			cfg: &config.Config{
				Rules: map[string]config.Rule{"r": {RuleID: "r", Filter: `finding["line"].contains("PRIVATE")`}},
			},
			filters: &mockFilterProvider{
				perRule: map[string]exprruntime.Program{"r": compile(`finding["line"].contains("PRIVATE")`)},
			},
			findings: []Finding{
				{RuleID: "r", Secret: "s", Line: "PRIVATE KEY abc"},
				{RuleID: "r", Secret: "s", Line: "public_key = abc"},
			},
			wantCount: 1,
			check: func(t *testing.T, got []Finding) {
				assert.Equal(t, "public_key = abc", got[0].Line)
			},
		},
		{
			// Regression: filter references finding.line but Line was not persisted at scan time.
			// The finding must be kept, not dropped, because finding["line"] == "".
			name: "per-rule filter sees empty line when Line not persisted",
			cfg: &config.Config{
				Rules: map[string]config.Rule{"r": {RuleID: "r", Filter: `finding["line"].contains("PRIVATE")`}},
			},
			filters: &mockFilterProvider{
				perRule: map[string]exprruntime.Program{"r": compile(`finding["line"].contains("PRIVATE")`)},
			},
			findings:  []Finding{{RuleID: "r", Secret: "s", Line: ""}},
			wantCount: 1,
		},
		{
			name:      "finding with unknown rule ID is kept",
			cfg:       &config.Config{Rules: map[string]config.Rule{"known": {RuleID: "known"}}},
			filters:   &mockFilterProvider{},
			findings:  []Finding{{RuleID: "unknown-rule", Secret: "s"}},
			wantCount: 1,
		},
		{
			name: "suppressed fingerprint is dropped",
			cfg:  &config.Config{Rules: map[string]config.Rule{"r": {RuleID: "r"}}},
			suppress: &mockSuppressor{fn: func(f Finding) bool {
				return f.Fingerprint == "fp-drop"
			}},
			findings: []Finding{
				{RuleID: "r", Secret: "kept", Fingerprint: "fp-keep"},
				{RuleID: "r", Secret: "dropped", Fingerprint: "fp-drop"},
			},
			wantCount: 1,
			check: func(t *testing.T, got []Finding) {
				assert.Equal(t, "kept", got[0].Secret)
			},
		},
		{
			name: "baseline suppression drops matching finding",
			cfg:  &config.Config{Rules: map[string]config.Rule{"r": {RuleID: "r"}}},
			suppress: &mockSuppressor{fn: func(f Finding) bool {
				return f.Secret == "baseline-secret"
			}},
			findings: []Finding{
				{RuleID: "r", Secret: "new-secret"},
				{RuleID: "r", Secret: "baseline-secret"},
			},
			wantCount: 1,
			check: func(t *testing.T, got []Finding) {
				assert.Equal(t, "new-secret", got[0].Secret)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NoError(t, tt.cfg.CompileFilters(nil))
			got, err := Replay(tt.findings, ReplayOptions{
				Config:      tt.cfg,
				ExprRuntime: rt,
				FilterSet:   tt.filters,
				Suppression: tt.suppress,
			})
			require.NoError(t, err)
			require.Len(t, got, tt.wantCount)
			if tt.wantCount > 0 && tt.check != nil {
				tt.check(t, got)
			}
		})
	}
}

// TestReplaySuppressionBeforeFilterEval is kept standalone because it verifies
// ordering via a stateful mock: the suppressor must fire before the filter runs.
func TestReplaySuppressionBeforeFilterEval(t *testing.T) {
	rt, err := exprruntime.New(nil)
	require.NoError(t, err)

	expr := `finding["secret"] == "x"`
	cfg := &config.Config{
		Filter: expr,
		Rules:  map[string]config.Rule{"r": {RuleID: "r"}},
	}
	require.NoError(t, cfg.CompileFilters(nil))

	prg, err := rt.CompileFilter(expr, nil)
	require.NoError(t, err)

	suppressed := false
	suppress := &mockSuppressor{fn: func(f Finding) bool {
		if f.Secret == "should-be-suppressed" {
			suppressed = true
			return true
		}
		return false
	}}

	got, err := Replay(
		[]Finding{{RuleID: "r", Secret: "should-be-suppressed"}},
		ReplayOptions{
			Config:      cfg,
			ExprRuntime: rt,
			FilterSet:   &mockFilterProvider{global: prg},
			Suppression: suppress,
		},
	)
	require.NoError(t, err)
	assert.Empty(t, got)
	assert.True(t, suppressed, "suppression must fire before filter evaluation")
}
