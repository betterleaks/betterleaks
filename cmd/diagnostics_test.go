package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDiagnosticsManagerRuleTimings(t *testing.T) {
	dir := t.TempDir()
	dm, err := NewDiagnosticsManager("rules,rules-csv", dir)
	require.NoError(t, err)
	require.True(t, dm.HasDiagType("rules"))
	require.True(t, dm.HasDiagType("rules-csv"))
	require.NotNil(t, dm.RuleTimings)

	dm.RuleTimings.Record("rule-1", 3*time.Millisecond)
	dm.RuleTimings.Record("rule-1", 1*time.Millisecond)
	dm.StopDiagnostics()

	textPath := filepath.Join(dir, "rule-timings.txt")
	csvPath := filepath.Join(dir, "rule-timings.csv")
	textBytes, err := os.ReadFile(textPath)
	require.NoError(t, err)
	require.Contains(t, string(textBytes), "rule-1")
	require.Contains(t, string(textBytes), "2")

	csvBytes, err := os.ReadFile(csvPath)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(csvBytes)), "\n")
	require.Len(t, lines, 2)
	require.Equal(t, "rule_id,total_duration_ns,total_duration,hits,avg_duration_ns,avg_duration", lines[0])
	require.Contains(t, lines[1], "rule-1,4000000,4ms,2,2000000,2ms")
}

func TestDiagnosticsManagerDefaultOutputDir(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	dm, err := NewDiagnosticsManager("rules", "")
	require.NoError(t, err)
	require.Equal(t, filepath.Join(dir, defaultDiagnosticsDir), dm.OutputDir)
	require.DirExists(t, dm.OutputDir)

	dm.RuleTimings.Record("rule-1", time.Millisecond)
	dm.StopDiagnostics()

	require.FileExists(t, filepath.Join(dm.OutputDir, "rule-timings.txt"))
}
