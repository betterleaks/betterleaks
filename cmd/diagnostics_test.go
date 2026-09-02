package cmd

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/internal/ruletiming"
)

func TestRuleTimingDiagnostics(t *testing.T) {
	outputDir := t.TempDir()
	manager, err := NewDiagnosticsManager("rules", outputDir, nil)
	require.NoError(t, err)

	collector := ruletiming.FromContext(manager.withContext(t.Context()))
	require.NotNil(t, collector)
	collector.Record("test-rule", time.Millisecond)
	require.NoError(t, manager.writeRuleTimings())

	report, err := os.ReadFile(filepath.Join(outputDir, "rule-timings.txt"))
	require.NoError(t, err)
	assert.Contains(t, string(report), "Rule Timings")
	assert.Contains(t, string(report), "test-rule")
	assert.NoFileExists(t, filepath.Join(outputDir, "rule-timings.csv"))
}
