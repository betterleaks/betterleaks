package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJSONWriterContract(t *testing.T) {
	for _, format := range []struct {
		name  string
		new   func(io.Writer) (FindingWriter, error)
		write func(io.Writer, []Finding) error
		empty string
	}{
		{"json", NewJSONWriter, WriteJSON, "[]\n"},
		{"jsonl", NewJSONLWriter, WriteJSONL, ""},
	} {
		for _, count := range []int{0, 2} {
			t.Run(fmt.Sprintf("%s/findings=%d", format.name, count), func(t *testing.T) {
				_, err := format.new(nil)
				require.Error(t, err)
				output, err := os.CreateTemp(t.TempDir(), "report")
				require.NoError(t, err)
				t.Cleanup(func() { _ = output.Close() })
				writer, err := format.new(output)
				require.NoError(t, err)
				var want []Finding
				for i := range count {
					finding := simpleFinding
					finding.RuleID = fmt.Sprintf("rule-%d", i)
					want = append(want, finding)
					require.NoError(t, writer.WriteFinding(finding))
					data, err := os.ReadFile(output.Name())
					require.NoError(t, err)
					require.Contains(t, string(data), finding.RuleID, "findings must be written before Close")
				}
				require.NoError(t, writer.Close())
				finished, err := os.ReadFile(output.Name())
				require.NoError(t, err)
				require.NoError(t, writer.Close())
				require.Error(t, writer.WriteFinding(simpleFinding))
				unchanged, err := os.ReadFile(output.Name())
				require.NoError(t, err)
				assert.Equal(t, finished, unchanged)
				_, err = output.WriteString("caller still owns output")
				require.NoError(t, err)

				var batch bytes.Buffer
				require.NoError(t, format.write(&batch, want))
				assert.Equal(t, string(finished), batch.String())
				if count == 0 {
					assert.Equal(t, format.empty, string(finished))
					return
				}
				var got []Finding
				if format.name == "json" {
					require.NoError(t, json.Unmarshal(finished, &got))
					assert.NotContains(t, string(finished), `"schema_version"`)
				} else {
					for _, line := range bytes.Split(bytes.TrimSpace(finished), []byte("\n")) {
						var record struct {
							SchemaVersion string  `json:"schema_version"`
							Finding       Finding `json:"finding"`
						}
						require.NoError(t, json.Unmarshal(line, &record))
						assert.Equal(t, SchemaVersion, record.SchemaVersion)
						got = append(got, record.Finding)
					}
				}
				assert.Equal(t, want, got)
			})
		}
	}
}

func TestJSONWritersPropagateOutputErrors(t *testing.T) {
	want := errors.New("output disconnected")
	for _, write := range []func(io.Writer, []Finding) error{WriteJSON, WriteJSONL} {
		require.ErrorIs(t, write(&failingPrettyWriter{err: want}, []Finding{simpleFinding}), want)
	}
}

func TestReportsSummarizeComponentAnalysis(t *testing.T) {
	analysis := Analysis{
		Status: ValidationStatusValid, Severity: SeverityHigh,
		StatusReason: "Authenticated", Reason: "Permissions resolved",
		Identity:       &AnalysisIdentity{Username: "owner"},
		Capabilities:   []Capability{CapabilityWrite},
		Metadata:       map[string]any{"acl": []string{"search", "addObject"}},
		StatusMetadata: map[string]any{"username": "owner"},
		Debug:          map[string]any{"validation": "diagnostics"},
	}
	finding := Finding{
		RuleID: "composite", Match: Match{Value: "primary-secret"}, Analysis: analysis,
		ComponentSets: []ComponentSet{
			{Components: []ComponentFinding{{RuleID: "part", Match: Match{Value: "component-secret"}}}, Analysis: analysis},
			{Analysis: Analysis{Status: ValidationStatusInvalid, StatusReason: "Unauthorized"}},
			{Analysis: Analysis{Reason: "No provider result"}},
		},
	}
	original := finding.Clone()
	for _, redact := range []bool{false, true} {
		for _, format := range []string{"json", "jsonl", "credential"} {
			t.Run(fmt.Sprintf("%s/redact=%t", format, redact), func(t *testing.T) {
				input := finding
				if redact {
					input = input.RedactedCopy(100)
				}
				var output bytes.Buffer
				switch format {
				case "json":
					require.NoError(t, WriteJSON(&output, []Finding{input}))
				case "jsonl":
					require.NoError(t, WriteJSONL(&output, []Finding{input}))
				case "credential":
					require.NoError(t, (CredentialReporter{Format: CredentialReportFormatJSONL}).Write(&output, NewCredentialReport(input, nil)))
				}
				var record map[string]any
				if format == "json" {
					var records []map[string]any
					require.NoError(t, json.Unmarshal(output.Bytes(), &records))
					require.Len(t, records, 1)
					record = records[0]
				} else {
					require.NoError(t, json.Unmarshal(output.Bytes(), &record))
				}
				if format == "jsonl" {
					assert.Equal(t, SchemaVersion, record["schema_version"])
					record = record["finding"].(map[string]any)
				}
				if format != "credential" {
					assert.NotContains(t, record, "schema_version")
				}
				expected, err := json.Marshal(analysis)
				require.NoError(t, err)
				actual, err := json.Marshal(record["analysis"])
				require.NoError(t, err)
				assert.JSONEq(t, string(expected), string(actual), "parent retains full analysis")
				sets := record["component_sets"].([]any)
				require.Len(t, sets, 3)
				assert.Equal(t, map[string]any{"status": "valid", "severity": "high"}, sets[0].(map[string]any)["analysis"])
				assert.Equal(t, map[string]any{"status": "invalid"}, sets[1].(map[string]any)["analysis"])
				assert.NotContains(t, sets[2].(map[string]any), "analysis")
				if redact {
					assert.NotContains(t, output.String(), "primary-secret")
					assert.NotContains(t, output.String(), "component-secret")
				}
				assert.Equal(t, original, finding, "reporting must not mutate the analyzer's results")
			})
		}
	}
}

var simpleFinding = Finding{
	Description: "",
	RuleID:      "test-rule",
	Confidence:  "medium",
	Match:       Match{Full: "line containing secret", Value: "a secret"},
	Location: Location{
		Path:        "auth.py",
		StartLine:   1,
		EndLine:     2,
		StartColumn: 1,
		EndColumn:   2,
	},
	Attributes: map[string]string{
		sources.AttrGitSHA:         "0000000000000000",
		sources.AttrGitAuthorName:  "John Doe",
		sources.AttrGitAuthorEmail: "johndoe@gmail.com",
		sources.AttrGitDate:        "10-19-2003",
		sources.AttrGitMessage:     "opps",
	},
}

func TestWriteJSON(t *testing.T) {
	var output bytes.Buffer
	require.NoError(t, WriteJSON(&output, []Finding{simpleFinding}))
	want, err := os.ReadFile("../testdata/expected/report/json_simple.json")
	require.NoError(t, err)
	assert.JSONEq(t, string(want), output.String())
}
