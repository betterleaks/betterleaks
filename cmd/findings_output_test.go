package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/ruletiming"
	"github.com/betterleaks/betterleaks/v2/pipeline"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/betterleaks/betterleaks/v2/version"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func decodeScanJSON(t *testing.T, data []byte) (report.ScanMetadata, []report.Finding) {
	t.Helper()
	var document struct {
		SchemaVersion string              `json:"schema_version"`
		Scan          report.ScanMetadata `json:"scan"`
		Findings      []report.Finding    `json:"findings"`
	}
	require.NoError(t, json.Unmarshal(data, &document))
	require.Equal(t, report.SchemaVersion, document.SchemaVersion)
	require.NotNil(t, document.Findings)
	require.False(t, document.Scan.Started.IsZero())
	require.Contains(t, []report.ScanState{report.ScanStateComplete, report.ScanStateIncomplete}, document.Scan.State)
	require.Equal(t, version.Version, document.Scan.BetterleaksVersion)
	require.False(t, document.Scan.Finished.Before(document.Scan.Started))
	assertScanCounts(t, document.Scan, document.Findings)
	return document.Scan, document.Findings
}

func decodeScanJSONL(t *testing.T, data []byte) (report.ScanMetadata, []report.Finding) {
	t.Helper()
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	require.NotEmpty(t, lines)
	var trailer struct {
		SchemaVersion string              `json:"schema_version"`
		Scan          report.ScanMetadata `json:"scan"`
	}
	require.NoError(t, json.Unmarshal(lines[len(lines)-1], &trailer))
	require.Equal(t, report.SchemaVersion, trailer.SchemaVersion)
	require.False(t, trailer.Scan.Started.IsZero())
	require.Contains(t, []report.ScanState{report.ScanStateComplete, report.ScanStateIncomplete}, trailer.Scan.State)
	require.Equal(t, version.Version, trailer.Scan.BetterleaksVersion)
	require.False(t, trailer.Scan.Finished.Before(trailer.Scan.Started))
	var findings []report.Finding
	for _, line := range lines[:len(lines)-1] {
		var record struct {
			SchemaVersion string         `json:"schema_version"`
			Finding       report.Finding `json:"finding"`
		}
		require.NoError(t, json.Unmarshal(line, &record))
		require.Equal(t, report.SchemaVersion, record.SchemaVersion)
		require.NotEmpty(t, record.Finding.RuleID)
		findings = append(findings, record.Finding)
	}
	assertScanCounts(t, trailer.Scan, findings)
	return trailer.Scan, findings
}

func assertScanCounts(t *testing.T, metadata report.ScanMetadata, findings []report.Finding) {
	t.Helper()
	assert.Equal(t, len(findings), metadata.NumFindings)
	c := metadata.ConfidenceCounts
	assert.Equal(t, metadata.NumFindings, c.High+c.Medium+c.Low+c.None+c.Other)
	s := metadata.SeverityCounts
	assert.Equal(t, metadata.NumFindings, s.High+s.Medium+s.Unknown+s.None)
	v := metadata.StatusCounts
	assert.Equal(t, metadata.NumFindings, v.Valid+v.Invalid+v.Revoked+v.NeedsValidation+v.Unknown+v.Error+v.None)
}

func TestFindingCollectorBreakdowns(t *testing.T) {
	for _, jsonl := range []bool{false, true} {
		t.Run(fmt.Sprintf("jsonl=%t", jsonl), func(t *testing.T) {
			flags, output := newFindingOutputCommand(jsonl, stdoutReportPath, false, 100)
			collector, err := newFindingCollector(flags, true, output)
			require.NoError(t, err)
			for i, input := range []struct {
				confidence string
				severity   report.Severity
				status     report.ValidationStatus
			}{
				{"high", report.SeverityHigh, report.ValidationStatusValid},
				{"high", report.SeverityMedium, report.ValidationStatusInvalid},
				{"medium", report.SeverityUnknown, report.ValidationStatusRevoked},
				{"low", report.SeverityNone, report.ValidationStatusNeedsValidation},
				{"", report.SeverityNone, report.ValidationStatusUnknown},
				{"custom", report.SeverityNone, report.ValidationStatusError},
				{"", report.SeverityNone, report.ValidationStatusNone},
			} {
				finding := testOutputFinding(fmt.Sprint(i))
				finding.Confidence = input.confidence
				finding.Analysis = report.Analysis{Severity: input.severity, Status: input.status}
				finding.ComponentSets = []report.ComponentSet{
					{Components: []report.ComponentFinding{{RuleID: "component"}}, Analysis: report.Analysis{Status: report.ValidationStatusValid}},
					{Components: []report.ComponentFinding{{RuleID: "component"}}, Analysis: report.Analysis{Status: report.ValidationStatusInvalid}},
				}
				require.NoError(t, collector.Add(finding))
			}
			require.NoError(t, collector.Close())
			var metadata report.ScanMetadata
			if jsonl {
				metadata, _ = decodeScanJSONL(t, output.Bytes())
			} else {
				metadata, _ = decodeScanJSON(t, output.Bytes())
			}
			assert.Equal(t, 7, metadata.NumFindings)
			assert.Equal(t, report.ConfidenceCounts{High: 2, Medium: 1, Low: 1, None: 2, Other: 1}, metadata.ConfidenceCounts)
			assert.Equal(t, report.SeverityCounts{High: 1, Medium: 1, Unknown: 1, None: 4}, metadata.SeverityCounts)
			assert.Equal(t, report.StatusCounts{Valid: 1, Invalid: 1, Revoked: 1, NeedsValidation: 1, Unknown: 1, Error: 1, None: 1}, metadata.StatusCounts)
		})
	}
}

func TestFindingCollectorPropagatesPrettyOutputError(t *testing.T) {
	want := errors.New("output disconnected")
	collector, err := newFindingCollector(&ScanFlags{}, true, testErrorWriter{err: want})
	require.NoError(t, err)
	require.ErrorIs(t, collector.Add(testOutputFinding("test")), want)
	require.Zero(t, collector.Count())
}

func TestFindingCollectorCountsHealthyOutputAfterWriteFailure(t *testing.T) {
	for _, failStdout := range []bool{false, true} {
		t.Run(fmt.Sprintf("fail_stdout=%t", failStdout), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "report.json")
			flags, stdout := newFindingOutputCommand(true, path, false, 0)
			collector, err := newFindingCollector(flags, true, stdout)
			require.NoError(t, err)
			require.NoError(t, collector.Add(testOutputFinding("first")))
			want := errors.New("output disconnected")
			broken, err := report.NewJSONLWriter(testErrorWriter{err: want})
			require.NoError(t, err)
			if failStdout {
				collector.stdoutWriter = broken
			} else {
				collector.reportWriter = broken
			}
			require.ErrorIs(t, collector.Add(testOutputFinding("second")), want)
			require.ErrorIs(t, collector.Add(testOutputFinding("late")), want)
			require.ErrorIs(t, collector.Close(), want)
			var metadata report.ScanMetadata
			var findings []report.Finding
			contents, err := os.ReadFile(path)
			require.NoError(t, err)
			if failStdout {
				metadata, findings = decodeScanJSON(t, contents)
				assert.NotContains(t, stdout.String(), `"scan"`)
			} else {
				metadata, findings = decodeScanJSONL(t, stdout.Bytes())
				assert.NotContains(t, string(contents), `"scan"`)
			}
			assert.Equal(t, report.ScanStateIncomplete, metadata.State)
			assert.Equal(t, 2, metadata.NumFindings)
			require.Len(t, findings, 2)
		})
	}
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

func TestCLIReportOutput(t *testing.T) {
	configPath := writeTestConfig(t, "[[rules]]\nid='token'\nregex='secret-[a-z]+'\n")
	for _, tc := range []struct {
		name   string
		output string
		flags  []string
		jsonl  bool
		empty  bool
		redact bool
	}{
		{name: "stdout JSON", output: "-"},
		{name: "stdout JSONL", output: "-", flags: []string{"--jsonl"}, jsonl: true},
		{name: "default JSONL redacted", flags: []string{"--jsonl", "--redact=100"}, jsonl: true, redact: true},
		{name: "silent JSON file overrides JSONL flag", output: "findings.json", flags: []string{"--silent", "--jsonl"}},
		{name: "silent JSONL file", output: "findings.jsonl", flags: []string{"--silent"}, jsonl: true},
		{name: "silent without report", flags: []string{"--silent"}},
		{name: "empty JSON", output: "-", empty: true},
		{name: "empty JSONL", output: "-", flags: []string{"--jsonl"}, jsonl: true, empty: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, stdout := newTestCLI(t)
			input := "secret-alpha\nsecret-beta\n"
			wantValues := []string{"secret-alpha", "secret-beta"}
			wantExit := 7
			if tc.empty {
				input, wantValues, wantExit = "", nil, 0
			}
			root.SetIn(strings.NewReader(input))
			var exitCode int
			root.runtime.exit = func(code int) { exitCode = code }
			args := []string{"stdin", "--config", configPath, "--offline", "--no-banner", "--exit-code=7"}
			outputPath := tc.output
			if outputPath != "" && outputPath != "-" {
				outputPath = filepath.Join(t.TempDir(), outputPath)
			}
			if outputPath != "" {
				args = append(args, "--output", outputPath)
			}
			root.SetArgs(append(args, tc.flags...))
			require.NoError(t, root.Execute())
			assert.Equal(t, wantExit, exitCode)
			data := stdout.Bytes()
			if outputPath != "" && outputPath != "-" {
				require.Empty(t, data)
				var err error
				data, err = os.ReadFile(outputPath)
				require.NoError(t, err)
			} else if outputPath == "" && !tc.jsonl {
				require.Empty(t, data)
				return
			}
			var metadata report.ScanMetadata
			var findings []report.Finding
			if tc.jsonl {
				metadata, findings = decodeScanJSONL(t, data)
			} else {
				metadata, findings = decodeScanJSON(t, data)
			}
			assert.Equal(t, report.ScanStateComplete, metadata.State)
			assert.Equal(t, report.ScanSource{Type: "stdin"}, metadata.Source)
			assert.Equal(t, uint64(len(input)), metadata.BytesScanned)
			var values []string
			for _, finding := range findings {
				assert.Equal(t, "token", finding.RuleID)
				values = append(values, finding.Match.Value)
			}
			if tc.redact {
				assert.NotContains(t, string(data), "secret-alpha")
				assert.NotContains(t, string(data), "secret-beta")
				wantValues = []string{"REDACTED", "REDACTED"}
			}
			assert.ElementsMatch(t, wantValues, values)
		})
	}
}

func TestScanSourceTargetRedaction(t *testing.T) {
	for _, tc := range []struct {
		kind, target, want string
	}{
		{"git", "https://user:private-password@example.com/repo?token=private-query#private-fragment", "https://example.com/repo"},
		{"git", "https://github.com/betterleaks/betterleaks", "https://github.com/betterleaks/betterleaks"},
		{"url", "https://user:private-password@example.com/a%2Fb?token=private-query#private-fragment", "https://example.com/a%2Fb"},
		{"url", "https://user:private-password@example.com/%zz?token=private-query", "[invalid URL]"},
		{"github", "https://user:private-password@github.com/owner/repo?token=private-query", "https://github.com/owner/repo"},
		{"gitlab", "https://user:private-password@gitlab.com/owner/repo?token=private-query", "https://gitlab.com/owner/repo"},
		{"huggingface", "hf://user:private-password@datasets/owner/repo?token=private-query", "hf://datasets/owner/repo"},
		{"s3", "s3://user:private-password@bucket/prefix?token=private-query", "s3://bucket/prefix"},
		{"filesystem", "./local-repo", "./local-repo"},
		{"git", "./local-repo", "./local-repo"},
	} {
		for _, jsonl := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%s/jsonl=%t", tc.kind, tc.want, jsonl), func(t *testing.T) {
				root, output := newTestCLI(t)
				flags := &ScanFlags{Output: stdoutReportPath, JSONL: jsonl}
				// URL credentials must be removed even without --redact.
				collector := mustNewFindingCollector(root.runtime, flags, true, time.Now(), &config.Config{}, tc.kind, tc.target)
				require.NoError(t, collector.Close())
				var metadata report.ScanMetadata
				if jsonl {
					metadata, _ = decodeScanJSONL(t, output.Bytes())
				} else {
					metadata, _ = decodeScanJSON(t, output.Bytes())
				}
				assert.Equal(t, report.ScanSource{Type: tc.kind, Targets: []string{tc.want}}, metadata.Source)
				assert.NotContains(t, output.String(), "private-")
			})
		}
	}
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
	_, findings := decodeScanJSON(t, contents)
	require.Empty(t, findings)
}

func TestFindingCollectorRejectsUnknownOutputExtension(t *testing.T) {
	path := filepath.Join(t.TempDir(), "findings.txt")
	flags, output := newFindingOutputCommand(false, path, false, 0)
	_, err := newFindingCollector(flags, true, output)
	require.EqualError(t, err, fmt.Sprintf("output path %q must end in .json or .jsonl", path))
}

func TestFindingCollectorFinalizesMetadata(t *testing.T) {
	for _, jsonl := range []bool{false, true} {
		for _, count := range []int{0, 1} {
			t.Run(fmt.Sprintf("jsonl=%t/findings=%d", jsonl, count), func(t *testing.T) {
				flags, output := newFindingOutputCommand(jsonl, stdoutReportPath, false, 0)
				collector, err := newFindingCollector(flags, true, output)
				require.NoError(t, err)
				if count > 0 {
					require.NoError(t, collector.Add(testOutputFinding("streamed")))
					require.Contains(t, output.String(), "streamed", "findings are written before finalization")
				}
				require.NotContains(t, output.String(), `"scan"`)
				require.NoError(t, collector.Close())
				finished := output.String()
				require.NoError(t, collector.Close())
				require.Equal(t, finished, output.String())
				var findings []report.Finding
				if jsonl {
					_, findings = decodeScanJSONL(t, output.Bytes())
				} else {
					_, findings = decodeScanJSON(t, output.Bytes())
				}
				require.Len(t, findings, count)
				require.Equal(t, count, collector.Count())
				require.Error(t, collector.Add(testOutputFinding("late")))
			})
		}
	}
}

func TestFindingSummaryCancellation(t *testing.T) {
	previousDiagnostics := diagnosticsManager
	diagnosticsManager = &DiagnosticsManager{}
	t.Cleanup(func() { diagnosticsManager = previousDiagnostics })
	for _, tc := range []struct {
		name     string
		scanErr  error
		canceled bool
	}{
		{"cancellation error", context.Canceled, false},
		{"canceled context", nil, true},
	} {
		for _, jsonl := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/jsonl=%t", tc.name, jsonl), func(t *testing.T) {
				root, output := newTestCLI(t)
				var exitCode int
				root.runtime.exit = func(code int) { exitCode = code }
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				root.runtime.Context = ctx
				if tc.canceled {
					cancel()
				}
				collector, err := newFindingCollector(&ScanFlags{Output: "-", JSONL: jsonl}, true, output)
				require.NoError(t, err)
				require.NoError(t, collector.Add(testOutputFinding("kept")))
				summary := pipeline.ScanSummary{BytesInspected: 123}
				findingSummaryAndExit(root.runtime, summary, false, collector, 7, collector.scan.Started, tc.scanErr)
				var metadata report.ScanMetadata
				var findings []report.Finding
				if jsonl {
					metadata, findings = decodeScanJSONL(t, output.Bytes())
				} else {
					metadata, findings = decodeScanJSON(t, output.Bytes())
				}
				assert.Equal(t, report.ScanStateIncomplete, metadata.State)
				assert.Equal(t, 1, exitCode)
				assert.Equal(t, summary.BytesInspected, metadata.BytesScanned)
				assert.Equal(t, collector.Count(), len(findings), "incomplete scans retain emitted findings")
			})
		}
	}
}

func TestFindingCollectorPropagatesMetadataWriteError(t *testing.T) {
	want := errors.New("metadata output disconnected")
	for _, outputPath := range []string{"", stdoutReportPath} {
		for _, jsonl := range []bool{false, true} {
			if outputPath == "" && !jsonl {
				continue // Pretty output has no metadata record.
			}
			flags, output := newFindingOutputCommand(jsonl, outputPath, false, 0)
			collector, err := newFindingCollector(flags, true, output)
			require.NoError(t, err)
			require.NoError(t, collector.Add(testOutputFinding("streamed")))
			collector.stdout = testErrorWriter{err: want}
			collector.reportOutput = nopWriteCloser{Writer: testErrorWriter{err: want}}
			require.ErrorIs(t, collector.Close(), want)
		}
	}
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
		Match:  report.Match{Full: "supersecret", Value: "supersecret", Line: "token=supersecret\n"},
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
		Match:         report.Match{Full: primary + " " + companion, Value: primary, Line: primary + " " + companion},
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
