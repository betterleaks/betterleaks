package report

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/betterleaks/betterleaks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteCSV(t *testing.T) {
	tests := []struct {
		findings       []betterleaks.Finding
		testReportName string
		expected       string
		wantEmpty      bool
	}{
		{
			testReportName: "simple",
			expected:       filepath.Join(expectPath, "report", "csv_simple.csv"),
			findings: []betterleaks.Finding{
				{
					RuleID:      "test-rule",
					Match:       "line containing secret",
					Secret:      "a secret",
					StartLine:   1,
					EndLine:     2,
					StartColumn: 1,
					EndColumn:   2,
					Fingerprint: "fingerprint",
					Tags:        []string{"tag1", "tag2", "tag3"},
					Metadata: map[string]string{
						betterleaks.MetaPath:          "auth.py",
						betterleaks.MetaSymlinkFile:   "",
						betterleaks.MetaCommitSHA:     "0000000000000000",
						betterleaks.MetaAuthorName:    "John Doe",
						betterleaks.MetaAuthorEmail:   "johndoe@gmail.com",
						betterleaks.MetaCommitDate:    "10-19-2003",
						betterleaks.MetaCommitMessage: "opps",
					},
					Fragment: &betterleaks.Fragment{
						Path: "auth.py",
						Resource: &betterleaks.Resource{
							Path: "auth.py",
							Metadata: map[string]string{
								betterleaks.MetaPath:          "auth.py",
								betterleaks.MetaSymlinkFile:   "",
								betterleaks.MetaCommitSHA:     "0000000000000000",
								betterleaks.MetaAuthorName:    "John Doe",
								betterleaks.MetaAuthorEmail:   "johndoe@gmail.com",
								betterleaks.MetaCommitDate:    "10-19-2003",
								betterleaks.MetaCommitMessage: "opps",
							},
						},
					},
				},
			}},
		{

			wantEmpty:      true,
			testReportName: "empty",
			expected:       filepath.Join(expectPath, "report", "this_should_not_exist.csv"),
			findings:       []betterleaks.Finding{},
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
