package report

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/betterleaks/betterleaks"
	"github.com/betterleaks/betterleaks/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteSarif(t *testing.T) {
	tests := []struct {
		findings       []betterleaks.Finding
		testReportName string
		expected       string
		wantEmpty      bool
		cfgName        string
	}{
		{
			cfgName:        "simple",
			testReportName: "simple",
			expected:       filepath.Join(expectPath, "report", "sarif_simple.sarif"),
			findings: []betterleaks.Finding{
				{

					RuleID:      "test-rule",
					Description: "A test rule",
					Match:       "line containing secret",
					Secret:      "a secret",
					StartLine:   1,
					EndLine:     2,
					StartColumn: 1,
					EndColumn:   2,
					Tags:        []string{"tag1", "tag2", "tag3"},
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
			}},
	}

	for _, test := range tests {
		t.Run(test.cfgName, func(t *testing.T) {
			tmpfile, err := os.Create(filepath.Join(t.TempDir(), test.testReportName+".json"))
			require.NoError(t, err)
			defer tmpfile.Close()

			reporter := SarifReporter{
				OrderedRules: []config.Rule{
					{
						RuleID:      "aws-access-key",
						Description: "AWS Access Key",
					},
					{
						RuleID:      "pypi",
						Description: "PyPI upload token",
					},
				},
			}
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
