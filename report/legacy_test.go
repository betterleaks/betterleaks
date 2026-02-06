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

// ---------------------------------------------------------------------------
// Legacy reporter tests.
//
// These tests ensure the legacy (gitleaks-compatible) reporters produce output
// that matches the legacy golden files (copied from the original gitleaks
// format before the betterleaks refactor).
// ---------------------------------------------------------------------------

func TestWriteLegacyJSON(t *testing.T) {
	tests := []struct {
		findings       []betterleaks.Finding
		testReportName string
		expected       string
		wantEmpty      bool
	}{
		{
			testReportName: "simple",
			expected:       filepath.Join(expectPath, "report", "json_simple_legacy.json"),
			findings:       []betterleaks.Finding{simpleFinding},
		},
		{
			testReportName: "empty",
			expected:       filepath.Join(expectPath, "report", "empty.json"),
			findings:       []betterleaks.Finding{},
		},
	}

	reporter := LegacyJsonReporter{}
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
			assert.Equal(t, wantStr, gotStr)
		})
	}
}

func TestWriteLegacyCSV(t *testing.T) {
	tests := []struct {
		findings       []betterleaks.Finding
		testReportName string
		expected       string
		wantEmpty      bool
	}{
		{
			testReportName: "simple",
			expected:       filepath.Join(expectPath, "report", "csv_simple_legacy.csv"),
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
			},
		},
		{
			testReportName: "empty",
			expected:       filepath.Join(expectPath, "report", "this_should_not_exist.csv"),
			findings:       []betterleaks.Finding{},
			wantEmpty:      true,
		},
	}

	reporter := LegacyCsvReporter{}
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

func TestWriteLegacySarif(t *testing.T) {
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
			expected:       filepath.Join(expectPath, "report", "sarif_simple_legacy.sarif"),
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
			},
		},
	}

	for _, test := range tests {
		t.Run(test.cfgName, func(t *testing.T) {
			tmpfile, err := os.Create(filepath.Join(t.TempDir(), test.testReportName+".sarif"))
			require.NoError(t, err)
			defer tmpfile.Close()

			reporter := LegacySarifReporter{
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

func TestWriteLegacyJunit(t *testing.T) {
	findings := []betterleaks.Finding{
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
	}

	tests := []struct {
		name     string
		findings []betterleaks.Finding
		expected string
	}{
		{
			name:     "simple",
			findings: findings,
			expected: filepath.Join(expectPath, "report", "junit_simple_legacy.xml"),
		},
		{
			name:     "empty",
			findings: []betterleaks.Finding{},
			expected: filepath.Join(expectPath, "report", "junit_empty_legacy.xml"),
		},
	}

	reporter := LegacyJunitReporter{}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tmpfile, err := os.Create(filepath.Join(t.TempDir(), test.name+".xml"))
			require.NoError(t, err)
			defer tmpfile.Close()

			err = reporter.Write(tmpfile, test.findings)
			require.NoError(t, err)
			assert.FileExists(t, tmpfile.Name())

			got, err := os.ReadFile(tmpfile.Name())
			require.NoError(t, err)

			want, err := os.ReadFile(test.expected)
			require.NoError(t, err)

			wantStr := lineEndingReplacer.Replace(string(want))
			gotStr := lineEndingReplacer.Replace(string(got))
			assert.Equal(t, wantStr, gotStr)
		})
	}
}
