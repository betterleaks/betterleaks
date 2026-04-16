package report

import (
	"encoding/json"
	"encoding/xml"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteJunit(t *testing.T) {
	tests := []struct {
		findings       []Finding
		testReportName string
		expected       string
		wantEmpty      bool
	}{
		{
			testReportName: "simple",
			expected:       filepath.Join(expectPath, "report", "junit_simple.xml"),
			findings: []Finding{
				{

					Description: "Test Rule",
					RuleID:      "test-rule",
					Match:       "line containing secret",
					Secret:      "a secret",
					StartLine:   1,
					EndLine:     2,
					StartColumn: 1,
					EndColumn:   2,
					Message:     "opps",
					File:        "auth.py",
					Commit:      "0000000000000000",
					Author:      "John Doe",
					Email:       "johndoe@gmail.com",
					Date:        "10-19-2003",
					Tags:        []string{},
				},
				{

					Description: "Test Rule",
					RuleID:      "test-rule",
					Match:       "line containing secret",
					Secret:      "a secret",
					StartLine:   2,
					EndLine:     3,
					StartColumn: 1,
					EndColumn:   2,
					Message:     "",
					File:        "auth.py",
					Commit:      "",
					Author:      "",
					Email:       "",
					Date:        "",
					Tags:        []string{},
				},
			},
		},
		{
			testReportName: "empty",
			expected:       filepath.Join(expectPath, "report", "junit_empty.xml"),
			findings:       []Finding{},
		},
	}

	reporter := JunitReporter{}
	for _, test := range tests {
		tmpfile, err := os.Create(filepath.Join(t.TempDir(), test.testReportName+".xml"))
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

		var wantSuites TestSuites
		require.NoError(t, xml.Unmarshal([]byte(wantStr), &wantSuites))
		normalizeJunitJSONPayloads(t, &wantSuites)

		var gotSuites TestSuites
		require.NoError(t, xml.Unmarshal([]byte(gotStr), &gotSuites))
		normalizeJunitJSONPayloads(t, &gotSuites)

		assert.Equal(t, wantSuites, gotSuites)
	}
}

func normalizeJunitJSONPayloads(t *testing.T, suites *TestSuites) {
	t.Helper()

	for i := range suites.TestSuites {
		for j := range suites.TestSuites[i].TestCases {
			data := suites.TestSuites[i].TestCases[j].Failure.Data
			if data == "" {
				continue
			}

			var payload any
			require.NoError(t, json.Unmarshal([]byte(data), &payload))

			normalized, err := json.Marshal(payload)
			require.NoError(t, err)

			suites.TestSuites[i].TestCases[j].Failure.Data = string(normalized)
		}
	}
}
