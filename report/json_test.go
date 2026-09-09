package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var simpleFinding = Finding{
	Description: "",
	RuleID:      "test-rule",
	Match:       "line containing secret",
	Secret:      "a secret",
	StartLine:   1,
	EndLine:     2,
	StartColumn: 1,
	EndColumn:   2,
	Message:     "opps",
	File:        "auth.py",
	SymlinkFile: "",
	Commit:      "0000000000000000",
	Author:      "John Doe",
	Email:       "johndoe@gmail.com",
	Date:        "10-19-2003",
	Tags:        []string{},
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

	reporter := JsonReporter{}
	for _, test := range tests {
		t.Run(test.testReportName, func(t *testing.T) {
			tmpfile, err := os.Create(filepath.Join(t.TempDir(), test.testReportName+".json"))
			require.NoError(t, err)
			defer tmpfile.Close()

			err = reporter.Write(tmpfile, test.findings)
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

func TestJSONFindingWriterStreams(t *testing.T) {
	var output bytes.Buffer
	reporter := JsonReporter{}
	w, err := reporter.NewWriter(&output)
	require.NoError(t, err)

	first := simpleFinding
	first.RuleID = "first"
	require.NoError(t, w.WriteFinding(first))
	assert.Contains(t, output.String(), `"RuleID": "first"`)

	second := simpleFinding
	second.RuleID = "second"
	require.NoError(t, w.WriteFinding(second))
	require.NoError(t, w.Close())

	var got []Finding
	require.NoError(t, json.Unmarshal(output.Bytes(), &got))
	require.Len(t, got, 2)
	assert.Equal(t, "first", got[0].RuleID)
	assert.Equal(t, "second", got[1].RuleID)
}

func TestJSONFindingWriterEmptyReport(t *testing.T) {
	var output bytes.Buffer
	w, err := (&JsonReporter{}).NewWriter(&output)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	assert.Equal(t, "[]\n", output.String())
}

func TestWriteJSONL(t *testing.T) {
	first := simpleFinding
	first.RuleID = "first"
	first.Secret = "one"
	second := simpleFinding
	second.RuleID = "second"
	second.Secret = "two"
	findings := []Finding{first, second}
	var output bytes.Buffer
	require.NoError(t, (&JsonlReporter{}).Write(testWriter{&output}, findings))

	lines := strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n")
	require.Len(t, lines, 2)
	for i, line := range lines {
		var got Finding
		require.NoError(t, json.Unmarshal([]byte(line), &got))
		assert.Equal(t, findings[i].RuleID, got.RuleID)
		assert.Equal(t, findings[i].Secret, got.Secret)
	}
}

func TestWriteEmptyJSONL(t *testing.T) {
	var output bytes.Buffer
	require.NoError(t, (&JsonlReporter{}).Write(testWriter{&output}, nil))
	assert.Empty(t, output.String())
}

func TestWriteJSONLWithEmbeddedNewlines(t *testing.T) {
	finding := simpleFinding
	finding.Message = "first line\nsecond line\nthird line"
	var output bytes.Buffer
	require.NoError(t, (&JsonlReporter{}).Write(testWriter{&output}, []Finding{finding}))
	require.Equal(t, 1, strings.Count(output.String(), "\n"))

	var got Finding
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(output.String())), &got))
	assert.Equal(t, finding.Message, got.Message)
}
