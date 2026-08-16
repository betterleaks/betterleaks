package report

import (
	"encoding/json"
	"os"
	"path/filepath"
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

func TestJSONLineField(t *testing.T) {
	reporter := JsonReporter{}

	t.Run("omitted when empty", func(t *testing.T) {
		f := simpleFinding // Line is zero-value ""
		tmp, err := os.Create(filepath.Join(t.TempDir(), "out.json"))
		require.NoError(t, err)
		defer tmp.Close()

		require.NoError(t, reporter.Write(tmp, []Finding{f}))
		data, err := os.ReadFile(tmp.Name())
		require.NoError(t, err)

		var findings []map[string]any
		require.NoError(t, json.Unmarshal(data, &findings))
		require.Len(t, findings, 1)
		_, hasLine := findings[0]["Line"]
		assert.False(t, hasLine, "Line should be absent when empty")
	})

	t.Run("round-trips when set", func(t *testing.T) {
		f := simpleFinding
		f.Line = "secret=hunter2"
		tmp, err := os.Create(filepath.Join(t.TempDir(), "out.json"))
		require.NoError(t, err)
		defer tmp.Close()

		require.NoError(t, reporter.Write(tmp, []Finding{f}))
		data, err := os.ReadFile(tmp.Name())
		require.NoError(t, err)

		var findings []Finding
		require.NoError(t, json.Unmarshal(data, &findings))
		require.Len(t, findings, 1)
		assert.Equal(t, "secret=hunter2", findings[0].Line)
	})
}
