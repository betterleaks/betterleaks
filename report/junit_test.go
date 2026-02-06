package report

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/betterleaks/betterleaks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteJunit(t *testing.T) {
	tests := []struct {
		findings       []betterleaks.Finding
		testReportName string
		expected       string
		wantEmpty      bool
	}{
		{
			testReportName: "simple",
			expected:       filepath.Join(expectPath, "report", "junit_simple.xml"),
			findings: []betterleaks.Finding{
				{

					Description: "Test Rule",
					RuleID:      "test-rule",
					Match:       "line containing secret",
					Secret:      "a secret",
					StartLine:   1,
					EndLine:     2,
					StartColumn: 1,
					EndColumn:   2,
					Tags:        []string{},
					Metadata: map[string]string{
						betterleaks.MetaPath:          "auth.py",
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
								betterleaks.MetaCommitSHA:     "0000000000000000",
								betterleaks.MetaAuthorName:    "John Doe",
								betterleaks.MetaAuthorEmail:   "johndoe@gmail.com",
								betterleaks.MetaCommitDate:    "10-19-2003",
								betterleaks.MetaCommitMessage: "opps",
							},
						},
					},
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
					Tags:        []string{},
					Metadata: map[string]string{
						betterleaks.MetaPath: "auth.py",
					},
					Fragment: &betterleaks.Fragment{
						Path: "auth.py",
						Resource: &betterleaks.Resource{
							Path: "auth.py",
							Metadata: map[string]string{
								betterleaks.MetaPath: "auth.py",
							},
						},
					},
				},
			},
		},
		{
			testReportName: "empty",
			expected:       filepath.Join(expectPath, "report", "junit_empty.xml"),
			findings:       []betterleaks.Finding{},
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
		assert.Equal(t, wantStr, gotStr)
	}
}
