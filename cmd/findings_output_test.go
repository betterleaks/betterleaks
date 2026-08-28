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

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources"
)

func TestFindingCollectorPrintsFindingsByDefault(t *testing.T) {
	cmd, _ := newFindingOutputCommand(false, "", false, 0)
	collector, err := newFindingCollector(cmd)
	require.NoError(t, err)

	output := captureFindingStdout(t, func() {
		require.NoError(t, collector.Add(testOutputFinding("default")))
		require.NoError(t, collector.Close())
	})

	require.Contains(t, output, "default")
	require.Equal(t, 1, collector.Count())
}

func TestFindingCollectorWritesJSONLToStdout(t *testing.T) {
	cmd, output := newFindingOutputCommand(true, "", false, 100)
	collector, err := newFindingCollector(cmd)
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
			cmd, _ := newFindingOutputCommand(false, path, true, 0)
			collector, err := newFindingCollector(cmd)
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
	cmd, _ := newFindingOutputCommand(false, path, true, 0)
	collector, err := newFindingCollector(cmd)
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
			cmd, output := newFindingOutputCommand(test.jsonl, report.StdoutReportPath, false, 0)
			collector, err := newFindingCollector(cmd)
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
	cmd, output := newFindingOutputCommand(true, path, true, 0)
	collector, err := newFindingCollector(cmd)
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

	cmd, _ := newFindingOutputCommand(false, relativeReportPath, true, 0)
	collector, err := newFindingCollector(cmd)
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
	cmd, _ := newFindingOutputCommand(false, path, false, 0)
	_, err := newFindingCollector(cmd)
	require.EqualError(t, err, "report path \""+path+"\" must end in .json or .jsonl")
}

func TestScanOutputFlags(t *testing.T) {
	for _, cmd := range scanCommands() {
		silent := cmd.Flags().Lookup("silent")
		require.NotNil(t, silent, cmd.Name())
		require.Equal(t, "s", silent.Shorthand)
		require.Equal(t, "false", silent.DefValue)
		require.Equal(t, "bool", silent.Value.Type())

		jsonl := cmd.Flags().Lookup("jsonl")
		require.NotNil(t, jsonl, cmd.Name())
		require.Equal(t, "bool", jsonl.Value.Type())

		reportFlag := cmd.Flags().Lookup("report")
		require.NotNil(t, reportFlag, cmd.Name())
		require.Equal(t, "r", reportFlag.Shorthand)
	}

	for _, name := range []string{"silent", "jsonl", "report"} {
		require.Nil(t, rootCmd.PersistentFlags().Lookup(name), name)
	}

	for _, removed := range []string{"report-path", "report-format", "verbose"} {
		require.Nil(t, rootCmd.PersistentFlags().Lookup(removed))
		for _, cmd := range scanCommands() {
			require.Nil(t, cmd.Flags().Lookup(removed), cmd.Name())
		}
	}
}

func TestDeprecatedScanCommandsRemoved(t *testing.T) {
	for _, command := range rootCmd.Commands() {
		require.NotContains(t, []string{"detect", "protect"}, command.Name())
	}
}

func TestZeroValueFindingCollectorCountsWithoutOutput(t *testing.T) {
	var collector findingCollector
	require.NoError(t, collector.Add(report.Finding{}))
	require.NoError(t, collector.Close())
	require.Equal(t, 1, collector.Count())
}

func newFindingOutputCommand(jsonl bool, reportPath string, silent bool, redact uint) (*cobra.Command, *bytes.Buffer) {
	cmd := &cobra.Command{}
	cmd.Flags().Bool("silent", silent, "")
	cmd.Flags().Bool("jsonl", jsonl, "")
	cmd.Flags().String("report", reportPath, "")
	cmd.Flags().Bool("no-color", true, "")
	cmd.Flags().Uint("redact", redact, "")
	output := new(bytes.Buffer)
	cmd.SetOut(output)
	return cmd, output
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
