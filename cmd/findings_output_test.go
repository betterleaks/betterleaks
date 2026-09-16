package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/betterleaks/betterleaks/v2/internal/ruletiming"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindingCollectorPropagatesPrettyOutputError(t *testing.T) {
	want := errors.New("output disconnected")
	collector, err := newFindingCollector(&ScanFlags{}, true, testErrorWriter{err: want})
	require.NoError(t, err)
	require.ErrorIs(t, collector.Add(testOutputFinding("test")), want)
}

func TestFindingCollectorPrintsFindingsByDefault(t *testing.T) {
	flags, sink := newFindingOutputCommand(false, "", false, 0)
	collector, err := newFindingCollector(flags, true, sink)
	require.NoError(t, err)
	finding := testOutputFinding("default")
	finding.Confidence = "low"
	finding.SetAttributes(map[string]string{
		sources.AttrPath:            "secrets.txt",
		sources.AttrResource:        sources.ResourceFileContent,
		sources.AttrFSFirstFragment: "true",
	})

	require.NoError(t, collector.Add(finding))
	require.NoError(t, collector.Close())
	output := sink.String()

	require.Contains(t, output, "default")
	require.Contains(t, output, "path ............ secrets.txt\n│   confidence ...... LOW\n│ attributes:")
	require.NotContains(t, output, sources.AttrFSFirstFragment)
	require.Equal(t, 1, collector.Count())
}

func TestFindingCollectorWritesJSONLToStdout(t *testing.T) {
	flags, output := newFindingOutputCommand(true, "", false, 100)
	collector, err := newFindingCollector(flags, true, output)
	require.NoError(t, err)

	require.NoError(t, collector.Add(testOutputFinding("first")))
	require.NoError(t, collector.Add(testOutputFinding("second")))
	require.NoError(t, collector.Close())

	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	require.Len(t, lines, 2)
	for i, line := range lines {
		var finding report.Finding
		require.NoError(t, json.Unmarshal([]byte(line), &finding))
		require.Equal(t, []string{"first", "second"}[i], finding.RuleID)
		require.Equal(t, "REDACTED", finding.Match.Value)
	}
}

func TestFindingCollectorWritesReportByExtension(t *testing.T) {
	tests := []struct {
		name      string
		extension string
	}{
		{name: "JSON", extension: ".json"},
		{name: "JSONL", extension: ".jsonl"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "findings"+test.extension)
			flags, output := newFindingOutputCommand(false, path, true, 0)
			collector, err := newFindingCollector(flags, true, output)
			require.NoError(t, err)
			require.NoError(t, collector.Add(testOutputFinding("reported")))
			require.NoError(t, collector.Close())

			contents, err := os.ReadFile(path)
			require.NoError(t, err)
			if test.extension == ".json" {
				var findings []report.Finding
				require.NoError(t, json.Unmarshal(contents, &findings))
				require.Len(t, findings, 1)
				require.Equal(t, "reported", findings[0].RuleID)
				return
			}

			var finding report.Finding
			require.NoError(t, json.Unmarshal(bytes.TrimSpace(contents), &finding))
			require.Equal(t, "reported", finding.RuleID)
		})
	}
}

func TestFindingCollectorReportToStdoutOwnsStream(t *testing.T) {
	tests := []struct {
		name  string
		jsonl bool
	}{
		{name: "JSON"},
		{name: "JSONL", jsonl: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			flags, output := newFindingOutputCommand(test.jsonl, stdoutReportPath, false, 0)
			collector, err := newFindingCollector(flags, true, output)
			require.NoError(t, err)
			require.False(t, collector.pretty)
			require.Nil(t, collector.stdoutWriter)
			require.NoError(t, collector.Add(testOutputFinding("stdout-report")))
			require.NoError(t, collector.Close())

			if test.jsonl {
				var finding report.Finding
				require.NoError(t, json.Unmarshal(bytes.TrimSpace(output.Bytes()), &finding))
				require.Equal(t, "stdout-report", finding.RuleID)
				return
			}
			var findings []report.Finding
			require.NoError(t, json.Unmarshal(output.Bytes(), &findings))
			require.Len(t, findings, 1)
		})
	}
}

func TestFindingCollectorSilentFindingsStillWritesReport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "findings.json")
	flags, output := newFindingOutputCommand(true, path, true, 0)
	collector, err := newFindingCollector(flags, true, output)
	require.NoError(t, err)
	require.NoError(t, collector.Add(testOutputFinding("silent")))
	require.NoError(t, collector.Close())

	require.Empty(t, output.String())
	contents, err := os.ReadFile(path)
	require.NoError(t, err)
	var findings []report.Finding
	require.NoError(t, json.Unmarshal(contents, &findings))
	require.Len(t, findings, 1)
}

func TestFindingCollectorSkipsReportBeforeFilesOpenIt(t *testing.T) {
	directory := t.TempDir()
	inputPath := filepath.Join(directory, "input.txt")
	blockedPath := filepath.Join(directory, "blocked.txt")
	reportPath := filepath.Join(directory, "findings.json")
	require.NoError(t, os.WriteFile(inputPath, []byte("input"), 0o600))
	require.NoError(t, os.WriteFile(blockedPath, []byte("blocked"), 0o600))
	t.Chdir(directory)

	flags, output := newFindingOutputCommand(false, "findings.json", true, 0)
	collector, err := newFindingCollector(flags, true, output)
	require.NoError(t, err)

	configuredSkip := func(attributes map[string]string) bool {
		return filepath.Clean(filepath.FromSlash(attributes[sources.AttrPath])) == blockedPath
	}
	files := &sources.Files{
		Path:       directory,
		Workers:    1,
		ShouldSkip: collector.FileSkipFunc(configuredSkip),
	}
	var visited []string
	err = files.Fragments(t.Context(), func(fragment sources.Fragment, err error) error {
		if err != nil {
			return err
		}
		visited = append(visited, filepath.Clean(filepath.FromSlash(fragment.Attr(sources.AttrPath))))
		return nil
	})
	require.NoError(t, err)
	require.NoError(t, collector.Close())

	require.Contains(t, visited, inputPath)
	require.NotContains(t, visited, blockedPath)
	require.NotContains(t, visited, reportPath)
	contents, err := os.ReadFile(reportPath)
	require.NoError(t, err)
	require.JSONEq(t, `[]`, string(contents))
}

func TestFindingCollectorRejectsUnknownOutputExtension(t *testing.T) {
	path := filepath.Join(t.TempDir(), "findings.txt")
	flags, output := newFindingOutputCommand(false, path, false, 0)
	_, err := newFindingCollector(flags, true, output)
	require.EqualError(t, err, fmt.Sprintf("output path %q must end in .json or .jsonl", path))
}

func TestZeroValueFindingCollectorCountsWithoutOutput(t *testing.T) {
	var collector findingCollector
	require.NoError(t, collector.Add(report.Finding{}))
	require.NoError(t, collector.Close())
	require.Equal(t, 1, collector.Count())
}

func newFindingOutputCommand(jsonl bool, outputPath string, silent bool, redact uint) (*ScanFlags, *bytes.Buffer) {
	flags := &ScanFlags{
		JSONL:  jsonl,
		Output: outputPath,
		Silent: silent,
		Redact: redactFlag(redact),
	}
	output := new(bytes.Buffer)
	return flags, output
}

func testOutputFinding(ruleID string) report.Finding {
	return report.Finding{
		RuleID: ruleID,
		Line:   "token=supersecret\n",
		Match:  report.Match{Full: "supersecret", Value: "supersecret"},
		Location: report.Location{
			StartLine:   1,
			EndLine:     1,
			StartColumn: 7,
			EndColumn:   17,
		},
		Tags: []string{},
	}
}

func TestFindingCollectorPrettyRedactsCompanionsAndAnalysis(t *testing.T) {
	flags, sink := newFindingOutputCommand(false, "", false, 100)
	collector, err := newFindingCollector(flags, true, sink)
	require.NoError(t, err)
	const primary, companion = "test-primary", "test-companion"
	finding := report.Finding{
		RuleID:        "multipart",
		Match:         report.Match{Full: primary + " " + companion, Value: primary},
		Line:          primary + " " + companion,
		Location:      report.Location{Path: "service.env", StartLine: 1, StartColumn: 1},
		Analysis:      report.Analysis{Status: report.ValidationStatusValid, Reason: primary + " " + companion},
		ComponentSets: []report.ComponentSet{{Components: []report.ComponentFinding{{RuleID: "part", Match: report.Match{Value: companion}}}}},
	}
	require.NoError(t, collector.Add(finding))
	require.NoError(t, collector.Close())
	output := sink.String()
	require.NotContains(t, output, primary)
	require.NotContains(t, output, companion)
	require.Contains(t, output, "service.env")
	require.Contains(t, output, "VALID")
	require.Equal(t, 1, strings.Count(output, "analysis:"))
	require.NotContains(t, output, "validation:")
	require.Equal(t, companion, finding.ComponentSets[0].Components[0].Match.Value)
}

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
