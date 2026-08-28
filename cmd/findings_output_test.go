package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources"
)

func TestFindingCollectorPrintsFindingsByDefault(t *testing.T) {
	flags, sink := newFindingOutputCommand(false, "", false, 0)
	collector, err := newFindingCollector(flags, true, sink)
	require.NoError(t, err)

	output := captureFindingStdout(t, func() {
		require.NoError(t, collector.Add(testOutputFinding("default")))
		require.NoError(t, collector.Close())
	})

	require.Contains(t, output, "default")
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
		require.Equal(t, "REDACTED", finding.Secret)
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

func TestFindingCollectorFinalizesPartialJSONReport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "partial.json")
	flags, output := newFindingOutputCommand(false, path, true, 0)
	collector, err := newFindingCollector(flags, true, output)
	require.NoError(t, err)
	require.NoError(t, collector.Add(testOutputFinding("before-interrupt")))

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, ctx.Err(), context.Canceled)
	require.NoError(t, collector.Close())

	contents, err := os.ReadFile(path)
	require.NoError(t, err)
	var findings []report.Finding
	require.NoError(t, json.Unmarshal(contents, &findings))
	require.Len(t, findings, 1)
	require.Equal(t, "before-interrupt", findings[0].RuleID)
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
			flags, output := newFindingOutputCommand(test.jsonl, report.StdoutReportPath, false, 0)
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
	workingDirectory, err := os.Getwd()
	require.NoError(t, err)
	relativeReportPath, err := filepath.Rel(workingDirectory, reportPath)
	require.NoError(t, err)

	flags, output := newFindingOutputCommand(false, relativeReportPath, true, 0)
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

func TestFindingCollectorRejectsUnknownReportExtension(t *testing.T) {
	path := filepath.Join(t.TempDir(), "findings.txt")
	flags, output := newFindingOutputCommand(false, path, false, 0)
	_, err := newFindingCollector(flags, true, output)
	require.EqualError(t, err, "report path \""+path+"\" must end in .json or .jsonl")
}

func TestScanOutputFlags(t *testing.T) {
	cli, err := parseCLIForTest(t, "dir", "-s", "--jsonl", "-r", "findings.json")
	require.NoError(t, err)
	require.True(t, cli.Directory.Silent)
	require.True(t, cli.Directory.JSONL)
	require.Equal(t, "findings.json", cli.Directory.Report)

	for _, removed := range []string{"report-path", "report-format", "verbose"} {
		_, err := parseCLIForTest(t, "dir", "--"+removed)
		require.ErrorContains(t, err, "unknown flag")
	}
}

func TestDeprecatedScanCommandsRemoved(t *testing.T) {
	for _, command := range []string{"detect", "protect"} {
		_, err := parseCLIForTest(t, command)
		require.Error(t, err)
	}
}

func TestZeroValueFindingCollectorCountsWithoutOutput(t *testing.T) {
	var collector findingCollector
	require.NoError(t, collector.Add(report.Finding{}))
	require.NoError(t, collector.Close())
	require.Equal(t, 1, collector.Count())
}

func newFindingOutputCommand(jsonl bool, reportPath string, silent bool, redact uint) (*ScanFlags, *bytes.Buffer) {
	flags := &ScanFlags{
		JSONL:  jsonl,
		Report: reportPath,
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
		Match:  "supersecret",
		Secret: "supersecret",
		Location: report.Location{
			StartLine:   1,
			EndLine:     1,
			StartColumn: 7,
			EndColumn:   17,
		},
		Tags: []string{},
	}
}

func captureFindingStdout(t *testing.T, fn func()) string {
	t.Helper()
	original := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	defer func() { os.Stdout = original }()

	fn()
	require.NoError(t, w.Close())
	contents, err := io.ReadAll(r)
	require.NoError(t, err)
	require.NoError(t, r.Close())
	return string(contents)
}
