package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/report"
)

func TestFindingCollectorCountsWithoutRetaining(t *testing.T) {
	collector := newTestFindingCollector(t, "", "", 0)
	payload := strings.Repeat("x", 32*1024)

	const count = 10_000
	for range count {
		require.NoError(t, collector.Add(report.Finding{ //nolint:exhaustruct // Only retained payload fields matter.
			Secret:       payload,
			MatchContext: payload,
		}))
	}

	require.Equal(t, count, collector.Count())
	require.Nil(t, collector.ReportFindings())
}

func TestFindingCollectorRetainsReportFindings(t *testing.T) {
	collector := newTestFindingCollector(t, filepath.Join(t.TempDir(), "findings.csv"), "csv", 0)
	var first report.Finding
	first.RuleID = "first"
	first.Secret = "one"
	var second report.Finding
	second.RuleID = "second"
	second.Secret = "two"
	want := []report.Finding{first, second}
	for _, finding := range want {
		require.NoError(t, collector.Add(finding))
	}

	require.Equal(t, len(want), collector.Count())
	require.Equal(t, want, collector.ReportFindings())
}

func TestZeroValueFindingCollectorCountsWithoutRetaining(t *testing.T) {
	var collector findingCollector
	var finding report.Finding
	require.NoError(t, collector.Add(finding))

	require.Equal(t, 1, collector.Count())
	require.Nil(t, collector.ReportFindings())
}

func TestFindingCollectorStreamsJSONWithoutRetaining(t *testing.T) {
	reportPath := filepath.Join(t.TempDir(), "findings.json")
	collector := newTestFindingCollector(t, reportPath, "json", 0)
	var first report.Finding
	first.RuleID = "first"
	first.Secret = "one"
	var second report.Finding
	second.RuleID = "second"
	second.Secret = "two"

	for _, finding := range []report.Finding{first, second} {
		require.NoError(t, collector.Add(finding))
		require.Nil(t, collector.ReportFindings())
	}

	require.True(t, collector.StreamsReport())
	require.NoError(t, collector.Close())

	contents, err := os.ReadFile(reportPath)
	require.NoError(t, err)
	var got []report.Finding
	require.NoError(t, json.Unmarshal(contents, &got))
	require.Len(t, got, 2)
	require.Equal(t, "first", got[0].RuleID)
	require.Equal(t, "second", got[1].RuleID)
}

func TestFindingCollectorStreamsAndRedactsInferredJSONL(t *testing.T) {
	reportPath := filepath.Join(t.TempDir(), "findings.jsonl")
	collector := newTestFindingCollector(t, reportPath, "", 100)
	var finding report.Finding
	finding.RuleID = "test-rule"
	finding.Match = "token=supersecret"
	finding.Secret = "supersecret"

	require.NoError(t, collector.Add(finding))
	require.Nil(t, collector.ReportFindings())

	require.True(t, collector.StreamsReport())
	require.NoError(t, collector.Close())

	contents, err := os.ReadFile(reportPath)
	require.NoError(t, err)
	require.Equal(t, 1, strings.Count(string(contents), "\n"))
	var got report.Finding
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(string(contents))), &got))
	require.Equal(t, "REDACTED", got.Secret)
	require.Equal(t, "token=REDACTED", got.Match)
}

func TestFindingCollectorFinalizesEmptyJSON(t *testing.T) {
	reportPath := filepath.Join(t.TempDir(), "findings.json")
	collector := newTestFindingCollector(t, reportPath, "", 0)

	require.True(t, collector.StreamsReport())
	require.NoError(t, collector.Close())
	contents, err := os.ReadFile(reportPath)
	require.NoError(t, err)
	require.Equal(t, "[]\n", string(contents))
}

func TestFindingCollectorInfersNDJSONAlias(t *testing.T) {
	reportPath := filepath.Join(t.TempDir(), "findings.ndjson")
	collector := newTestFindingCollector(t, reportPath, "", 0)
	var finding report.Finding
	finding.RuleID = "test-rule"

	require.NoError(t, collector.Add(finding))
	require.True(t, collector.StreamsReport())
	require.NoError(t, collector.Close())
	require.Nil(t, collector.ReportFindings())
}

func TestFindingCollectorRetainsNonStreamingReports(t *testing.T) {
	reportPath := filepath.Join(t.TempDir(), "findings.csv")
	collector := newTestFindingCollector(t, reportPath, "csv", 0)
	var finding report.Finding
	finding.RuleID = "test-rule"
	finding.Secret = "secret"

	require.NoError(t, collector.Add(finding))
	require.False(t, collector.StreamsReport())
	require.NoError(t, collector.Close())
	require.Equal(t, []report.Finding{finding}, collector.ReportFindings())
}

func TestNewFindingCollectorRejectsUnknownReportFormat(t *testing.T) {
	reportPath := filepath.Join(t.TempDir(), "findings.xml")
	_, err := newFindingCollector(newReportCommand(t, reportPath, "xml", 0))
	require.EqualError(t, err, `unknown report format "xml"`)
}

func newTestFindingCollector(t *testing.T, reportPath, reportFormat string, redact uint) *findingCollector {
	t.Helper()
	collector, err := newFindingCollector(newReportCommand(t, reportPath, reportFormat, redact))
	require.NoError(t, err)
	return collector
}

func newReportCommand(t *testing.T, reportPath, reportFormat string, redact uint) *cobra.Command {
	t.Helper()
	cmd := new(cobra.Command)
	cmd.Flags().String("report-path", reportPath, "")
	cmd.Flags().String("report-format", reportFormat, "")
	cmd.Flags().String("report-template", "", "")
	cmd.Flags().Uint("redact", redact, "")
	return cmd
}
