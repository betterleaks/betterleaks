package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJSONWritersRespectOutputOwnership(t *testing.T) {
	for name, newWriter := range map[string]func(io.Writer) (FindingWriter, error){
		"json": NewJSONWriter, "jsonl": NewJSONLWriter,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := newWriter(nil)
			require.Error(t, err)
			var output bytes.Buffer
			writer, err := newWriter(&output)
			require.NoError(t, err)
			require.NoError(t, writer.WriteFinding(simpleFinding))
			require.NoError(t, writer.Close())
			finished := output.String()
			require.NoError(t, writer.Close())
			require.Equal(t, finished, output.String())
			require.Error(t, writer.WriteFinding(simpleFinding))
			_, err = output.WriteString("caller still owns output")
			require.NoError(t, err)
		})
	}
}

func TestJSONWritersPropagateOutputErrors(t *testing.T) {
	want := errors.New("output disconnected")
	for _, write := range []func(io.Writer, []Finding) error{WriteJSON, WriteJSONL} {
		require.ErrorIs(t, write(&failingPrettyWriter{err: want}, []Finding{simpleFinding}), want)
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
	Tags: []string{},
}

func TestJSONFindingWriterStreams(t *testing.T) {
	var output bytes.Buffer
	writer, err := NewJSONWriter(&output)
	require.NoError(t, err)

	first := simpleFinding
	first.RuleID = "first"
	second := simpleFinding
	second.RuleID = "second"
	require.NoError(t, writer.WriteFinding(first))
	require.NoError(t, writer.WriteFinding(second))
	require.NoError(t, writer.Close())

	var findings []Finding
	require.NoError(t, json.Unmarshal(output.Bytes(), &findings))
	require.Len(t, findings, 2)
	require.Equal(t, "first", findings[0].RuleID)
	require.Equal(t, "second", findings[1].RuleID)
}

func TestJSONFindingWriterFinalizesEmptyReport(t *testing.T) {
	var output bytes.Buffer
	writer, err := NewJSONWriter(&output)
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	require.Equal(t, "[]\n", output.String())
}

func TestWriteJSONL(t *testing.T) {
	first := simpleFinding
	first.RuleID = "first"
	second := simpleFinding
	second.RuleID = "second"

	var output bytes.Buffer
	require.NoError(t, WriteJSONL(testWriter{Buffer: &output}, []Finding{first, second}))

	lines := strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n")
	require.Len(t, lines, 2)
	for i, line := range lines {
		var finding Finding
		require.NoError(t, json.Unmarshal([]byte(line), &finding))
		require.Equal(t, []string{"first", "second"}[i], finding.RuleID)
	}
}

func TestWriteEmptyJSONL(t *testing.T) {
	var output bytes.Buffer
	require.NoError(t, WriteJSONL(testWriter{Buffer: &output}, nil))
	require.Empty(t, output.String())
}

func TestWriteJSON(t *testing.T) {
	tests := []struct {
		findings       []Finding
		testReportName string
		expected       string
		wantEmpty      bool
	}{
		{
			testReportName: "simple",
			expected:       filepath.Join(expectPath, "report", "json_simple.json"),
			findings: []Finding{
				simpleFinding,
			}},
		{

			testReportName: "empty",
			expected:       filepath.Join(expectPath, "report", "empty.json"),
			findings:       []Finding{}},
	}

	for _, test := range tests {
		t.Run(test.testReportName, func(t *testing.T) {
			tmpfile, err := os.Create(filepath.Join(t.TempDir(), test.testReportName+".json"))
			require.NoError(t, err)
			defer tmpfile.Close()

			err = WriteJSON(tmpfile, test.findings)
			require.NoError(t, err)
			assert.FileExists(t, tmpfile.Name())

			got, err := os.ReadFile(tmpfile.Name())
			require.NoError(t, err)
			if test.wantEmpty {
				assert.Empty(t, got)
				return
			}

			want, err := os.ReadFile(test.expected)
			require.NoError(t, err)

			wantStr := lineEndingReplacer.Replace(string(want))
			gotStr := lineEndingReplacer.Replace(string(got))

			var wantJSON any
			require.NoError(t, json.Unmarshal([]byte(wantStr), &wantJSON))

			var gotJSON any
			require.NoError(t, json.Unmarshal([]byte(gotStr), &gotJSON))

			assert.Equal(t, wantJSON, gotJSON)
		})
	}
}
