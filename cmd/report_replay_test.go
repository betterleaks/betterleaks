package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/detect"
	"github.com/betterleaks/betterleaks/internal/exprruntime"
	"github.com/betterleaks/betterleaks/report"
)

func writeFixtureReport(t *testing.T, dir string, findings []report.Finding) string {
	t.Helper()
	data, err := json.Marshal(findings)
	require.NoError(t, err)
	path := filepath.Join(dir, "input.json")
	require.NoError(t, os.WriteFile(path, data, 0600))
	return path
}

func TestLoadReplayInput(t *testing.T) {
	fixture := []report.Finding{
		{RuleID: "rule-a", Secret: "s3cr3t", Fingerprint: "fp1"},
		{RuleID: "rule-b", Secret: "another", Fingerprint: "fp2"},
	}
	path := writeFixtureReport(t, t.TempDir(), fixture)

	got, err := loadReplayInput(path)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "rule-a", got[0].RuleID)
	assert.Equal(t, "s3cr3t", got[0].Secret)
	assert.Equal(t, "rule-b", got[1].RuleID)
}

func TestLoadReplayInputInvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	require.NoError(t, os.WriteFile(path, []byte("not json"), 0600))

	_, err := loadReplayInput(path)
	assert.Error(t, err)
}

func TestLoadReplayInputMissingFile(t *testing.T) {
	_, err := loadReplayInput(filepath.Join(t.TempDir(), "nonexistent.json"))
	assert.Error(t, err)
}

// TestReplayCmdPipeline exercises the full path from JSON file → loadReplayInput →
// report.Replay → result, simulating what runReplay does without invoking cobra.
func TestReplayCmdPipeline(t *testing.T) {
	fixture := []report.Finding{
		{RuleID: "test-rule", Secret: "keep-me", Attributes: map[string]string{}},
		{RuleID: "test-rule", Secret: "drop-me", Attributes: map[string]string{}},
	}
	path := writeFixtureReport(t, t.TempDir(), fixture)

	findings, err := loadReplayInput(path)
	require.NoError(t, err)

	filterExpr := `finding["secret"] == "drop-me"`
	cfg := &config.Config{
		Filter: filterExpr,
		Rules:  map[string]config.Rule{"test-rule": {RuleID: "test-rule", Filter: filterExpr}},
	}
	require.NoError(t, cfg.CompileFilters(nil))

	rt, err := exprruntime.New(nil)
	require.NoError(t, err)

	results, err := report.Replay(findings, report.ReplayOptions{
		Config:      cfg,
		ExprRuntime: rt,
		FilterSet:   detect.NewFilterSet(cfg, rt),
	})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "keep-me", results[0].Secret)
}
