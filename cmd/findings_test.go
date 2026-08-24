package cmd

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/report"
)

func collectorTestCommand(path, format, template string, redact uint) *cobra.Command {
	cmd := reportTestCommand(path, format, template)
	cmd.Flags().Uint("redact", redact, "")
	cmd.Flags().Bool("verbose", false, "")
	cmd.Flags().Bool("legacy-print", false, "")
	cmd.Flags().Bool("no-color", true, "")
	return cmd
}

func TestFindingCollectorDoesNotRetainStandardReportFindings(t *testing.T) {
	cmd := collectorTestCommand(filepath.Join(t.TempDir(), "findings.json"), "json", "", 0)
	findings := newFindingCollector(cmd)
	t.Cleanup(func() { require.NoError(t, findings.Close()) })

	const count = 1_000
	for i := 0; i < count; i++ {
		require.NoError(t, findings.Add(report.Finding{
			RuleID: "example",
			Secret: "secret",
			ValidationMeta: map[string]any{
				"integer": int64(9_007_199_254_740_993),
			},
		}))
	}

	require.Equal(t, count, findings.Len())
	require.Empty(t, findings.retained)
	require.NotNil(t, findings.file)

	for pass := 0; pass < 2; pass++ {
		visited := 0
		require.NoError(t, findings.Iterate(func(finding report.Finding) error {
			visited++
			require.Equal(t, "example", finding.RuleID)
			require.Equal(t, json.Number("9007199254740993"), finding.ValidationMeta["integer"])
			return nil
		}))
		require.Equal(t, count, visited)
	}
}

func TestFindingCollectorDoesNotStoreWhenReportIsDisabled(t *testing.T) {
	findings := newFindingCollector(collectorTestCommand("", "", "", 0))
	require.NoError(t, findings.Add(report.Finding{Secret: "do not retain me"}))
	require.Equal(t, 1, findings.Len())
	require.Nil(t, findings.file)
	require.Empty(t, findings.retained)
	require.NoError(t, findings.Close())
}

func TestFindingCollectorRetainsTemplateInput(t *testing.T) {
	findings := newFindingCollector(collectorTestCommand("report.txt", "template", "report.tmpl", 0))
	t.Cleanup(func() { require.NoError(t, findings.Close()) })

	want := report.Finding{
		RuleID: "example",
		Line:   "templates may read this non-JSON field",
		ValidationMeta: map[string]any{
			"integer": int64(42),
		},
	}
	require.NoError(t, findings.Add(want))
	require.Nil(t, findings.file)

	got, err := findings.Slice()
	require.NoError(t, err)
	require.Equal(t, []report.Finding{want}, got)
}

func TestCollectedTemplateReportReceivesFindingSlice(t *testing.T) {
	dir := t.TempDir()
	templatePath := filepath.Join(dir, "report.tmpl")
	require.NoError(t, os.WriteFile(templatePath, []byte(`{{ len . }}:{{ (index . 0).Line }}`), 0o600))
	reportPath := filepath.Join(dir, "report.txt")
	cmd := collectorTestCommand(reportPath, "template", templatePath, 0)
	findings := newFindingCollector(cmd)
	require.NoError(t, findings.Add(report.Finding{Line: "complete line"}))

	require.NoError(t, writeCollectedFindingsReport(cmd, &config.Config{}, findings))
	require.NoError(t, findings.Close())
	contents, err := os.ReadFile(reportPath)
	require.NoError(t, err)
	require.Equal(t, "1:complete line", string(contents))
}

func TestCollectedJSONReportRedactsAndStreams(t *testing.T) {
	path := filepath.Join(t.TempDir(), "findings.json")
	cmd := collectorTestCommand(path, "json", "", 100)
	findings := newFindingCollector(cmd)

	require.NoError(t, findings.Add(report.Finding{
		RuleID:        "example",
		Match:         "token=secret",
		Secret:        "secret",
		CaptureGroups: map[string]string{"token": "secret"},
	}))
	require.NoError(t, writeCollectedFindingsReport(cmd, &config.Config{}, findings))
	require.NoError(t, findings.Close())

	contents, err := os.ReadFile(path)
	require.NoError(t, err)
	var got []report.Finding
	require.NoError(t, json.Unmarshal(contents, &got))
	require.Len(t, got, 1)
	require.Equal(t, "REDACTED", got[0].Secret)
	require.Equal(t, "token=REDACTED", got[0].Match)
	require.Equal(t, "REDACTED", got[0].CaptureGroups["token"])
}

func TestCollectedReportsReplaySpool(t *testing.T) {
	tests := []struct {
		format string
		ext    string
		check  func(*testing.T, []byte)
	}{
		{
			format: "csv",
			ext:    ".csv",
			check: func(t *testing.T, contents []byte) {
				records, err := csv.NewReader(bytes.NewReader(contents)).ReadAll()
				require.NoError(t, err)
				require.Len(t, records, 3)
			},
		},
		{
			format: "junit",
			ext:    ".xml",
			check: func(t *testing.T, contents []byte) {
				var suites report.TestSuites
				require.NoError(t, xml.Unmarshal(contents, &suites))
				require.Len(t, suites.TestSuites, 1)
				require.Len(t, suites.TestSuites[0].TestCases, 2)
			},
		},
		{
			format: "sarif",
			ext:    ".sarif",
			check: func(t *testing.T, contents []byte) {
				require.True(t, json.Valid(contents))
				var sarif report.Sarif
				require.NoError(t, json.Unmarshal(contents, &sarif))
				require.Len(t, sarif.Runs, 1)
				require.Len(t, sarif.Runs[0].Results, 2)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.format, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "findings"+test.ext)
			cmd := collectorTestCommand(path, test.format, "", 0)
			findings := newFindingCollector(cmd)
			for _, ruleID := range []string{"first", "second"} {
				require.NoError(t, findings.Add(report.Finding{
					RuleID: ruleID,
					Match:  "token=secret",
					Secret: "secret",
				}))
			}

			require.NoError(t, writeCollectedFindingsReport(cmd, &config.Config{}, findings))
			require.NoError(t, findings.Close())
			contents, err := os.ReadFile(path)
			require.NoError(t, err)
			test.check(t, contents)
		})
	}
}

func TestFindingCollectorRemovesNamedSpool(t *testing.T) {
	findings := newFindingCollector(collectorTestCommand("report.json", "json", "", 0))
	require.NoError(t, findings.Add(report.Finding{RuleID: "example"}))

	path := findings.tempPath
	if path != "" {
		_, err := os.Stat(path)
		require.NoError(t, err)
	}
	require.NoError(t, findings.Close())
	if path != "" {
		_, err := os.Stat(path)
		require.ErrorIs(t, err, os.ErrNotExist)
	}
}
