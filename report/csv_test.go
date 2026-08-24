package report

import (
	"bytes"
	"encoding/csv"
	"os"
	"path/filepath"
	"testing"

	"github.com/betterleaks/betterleaks/sources"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteCSV(t *testing.T) {
	tests := []struct {
		findings       []Finding
		testReportName string
		expected       string
		wantEmpty      bool
	}{
		{
			testReportName: "simple",
			expected:       filepath.Join(expectPath, "report", "csv_simple.csv"),
			findings: []Finding{
				{
					RuleID:      "test-rule",
					Match:       "line containing secret",
					Secret:      "a secret",
					StartLine:   1,
					EndLine:     2,
					StartColumn: 1,
					EndColumn:   2,
					Attributes: testGitAttributes(
						"auth.py",
						"0000000000000000",
						"John Doe",
						"johndoe@gmail.com",
						"10-19-2003",
						"opps",
					),
					Fingerprint: "fingerprint",
					Tags:        []string{"tag1", "tag2", "tag3"},
				},
			}},
		{

			wantEmpty:      true,
			testReportName: "empty",
			expected:       filepath.Join(expectPath, "report", "this_should_not_exist.csv"),
			findings:       []Finding{},
		},
	}

	reporter := CsvReporter{}
	for _, test := range tests {
		t.Run(test.testReportName, func(t *testing.T) {
			tmpfile, err := os.Create(filepath.Join(t.TempDir(), test.testReportName+".csv"))
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
			assert.Equal(t, wantStr, gotStr)
		})
	}
}

func TestWriteCSVIncludesLinkWhenLaterFindingHasOne(t *testing.T) {
	var output bytes.Buffer
	findings := []Finding{
		{RuleID: "first"},
		{RuleID: "second", Attributes: map[string]string{sources.AttrURL: "https://example.test/finding"}},
	}
	require.NoError(t, (&CsvReporter{}).Write(&output, findings))

	records, err := csv.NewReader(bytes.NewReader(output.Bytes())).ReadAll()
	require.NoError(t, err)
	require.Len(t, records, 3)
	require.Equal(t, "Link", records[0][len(records[0])-1])
	require.Equal(t, findings[1].Attr(sources.AttrURL), records[2][len(records[2])-1])
}
