package detect

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources"
)

func baselineAttributes(path, commit, author, email, date, message string) map[string]string {
	return map[string]string{
		sources.AttrPath:           path,
		sources.AttrGitSHA:         commit,
		sources.AttrGitAuthorName:  author,
		sources.AttrGitAuthorEmail: email,
		sources.AttrGitDate:        date,
		sources.AttrGitMessage:     message,
	}
}

func baselineFinding(match, secret, commit, date string) report.Finding {
	return report.Finding{
		RuleID:      "private-key",
		Description: "Identified a Private Key",
		StartLine:   1,
		EndLine:     15,
		StartColumn: 1,
		EndColumn:   30,
		Match:       match,
		Secret:      secret,
		Attributes: baselineAttributes(
			"key.txt",
			commit,
			"James Bond",
			"jbond@gov.co.uk",
			date,
			"init",
		),
	}
}

func TestIsNew(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		findings report.Finding
		redact   uint
		baseline []report.Finding
		expect   bool
	}{
		"new - commit doesn't match baseline": {
			findings: report.Finding{Attributes: baselineAttributes("", "0000", "a", "", "", "")},
			baseline: []report.Finding{{Attributes: baselineAttributes("", "0002", "a", "", "", "")}},
			expect:   true,
		},
		"new - redacted, different baseline": {
			findings: baselineFinding("REDACTED", "REDACTED", "6d3ba1f7653822c0f8ac9a9af56daaa2cd8bbcad", "2025-03-02T15:10:40Z"),
			baseline: []report.Finding{
				baselineFinding("private key material", "private key material", "e55e00ca1690a6b5b612d28b3d9ada3fd1775ac4", "2025-02-02T17:45:30Z"),
			},
			expect: true,
		},
		"not new - commit+author matches": {
			findings: report.Finding{Attributes: baselineAttributes("", "0000", "a", "", "", "")},
			baseline: []report.Finding{{Attributes: baselineAttributes("", "0000", "a", "", "", "")}},
			expect:   false,
		},
		"not new - commit+author matches, tags ignored": {
			findings: report.Finding{
				Attributes: baselineAttributes("", "0000", "a", "", "", ""),
				Tags:       []string{"a", "b"},
			},
			baseline: []report.Finding{
				{
					Attributes: baselineAttributes("", "0000", "a", "", "", ""),
					Tags:       []string{"a", "c"},
				},
			},
			expect: false, // Updated tags doesn't make it a new finding
		},
		"not new - redacted, everything else matches": {
			findings: baselineFinding("REDACTED", "REDACTED", "e55e00ca1690a6b5b612d28b3d9ada3fd1775ac4", "2025-02-02T17:45:30Z"),
			redact:   100,
			baseline: []report.Finding{
				baselineFinding("private key material", "private key material", "e55e00ca1690a6b5b612d28b3d9ada3fd1775ac4", "2025-02-02T17:45:30Z"),
			},
			expect: false,
		},
		"new - unredacted secret differs": {
			findings: baselineFinding("first", "first", "e55e00ca1690a6b5b612d28b3d9ada3fd1775ac4", "2025-02-02T17:45:30Z"),
			baseline: []report.Finding{
				baselineFinding("second", "second", "e55e00ca1690a6b5b612d28b3d9ada3fd1775ac4", "2025-02-02T17:45:30Z"),
			},
			expect: true,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, test.expect, IsNew(test.findings, test.redact, test.baseline))
		})
	}
}

func TestFileLoadBaseline(t *testing.T) {
	t.Parallel()
	findings, err := LoadBaseline("../testdata/baseline/baseline.json")
	require.NoError(t, err)
	require.Len(t, findings, 2)
	assert.Equal(t, "detect/detect_test.go", findings[0].Attr(sources.AttrPath))
	assert.Equal(t, "9326f35380636bcbe61e94b0584d1618c4b5c2c2", findings[0].Attr(sources.AttrGitSHA))

	tests := []struct {
		Filename      string
		ExpectedError string
	}{
		{
			Filename:      "../testdata/baseline/baseline.csv",
			ExpectedError: "decode baseline",
		},
		{
			Filename:      "../testdata/baseline/baseline.sarif",
			ExpectedError: "decode baseline",
		},
		{
			Filename:      "../testdata/baseline/notfound.json",
			ExpectedError: "open baseline",
		},
	}

	for _, test := range tests {
		_, err := LoadBaseline(test.Filename)
		assert.ErrorContains(t, err, test.ExpectedError)
	}

	_, err = LoadBaseline("../testdata/baseline/notfound.json")
	assert.ErrorIs(t, err, os.ErrNotExist)
	_, err = LoadBaseline("../testdata/baseline/baseline.csv")
	var syntaxError *json.SyntaxError
	assert.ErrorAs(t, err, &syntaxError)
}

func TestLoadBaselineRejectsRemovedFindingFields(t *testing.T) {
	path := t.TempDir() + "/baseline.json"
	require.NoError(t, os.WriteFile(path, []byte(`[{"RuleID":"test","File":"secret.txt"}]`), 0o600))

	_, err := LoadBaseline(path)
	require.ErrorContains(t, err, `finding 0 uses removed field "File"`)
	require.ErrorContains(t, err, "regenerate the baseline")
}

func TestIgnoreIssuesInBaseline(t *testing.T) {
	t.Parallel()
	tests := []struct {
		findings    []report.Finding
		baseline    []report.Finding
		expectCount int
	}{
		{
			findings: []report.Finding{
				{Attributes: baselineAttributes("", "5", "a", "", "", "")},
			},
			baseline: []report.Finding{
				{Attributes: baselineAttributes("", "5", "a", "", "", "")},
			},
			expectCount: 0,
		},
		{
			findings: []report.Finding{
				{
					Attributes:  baselineAttributes("", "5", "a", "", "", ""),
					Fingerprint: "a",
				},
			},
			baseline: []report.Finding{
				{
					Attributes:  baselineAttributes("", "5", "a", "", "", ""),
					Fingerprint: "b",
				},
			},
			expectCount: 0,
		},
	}

	for _, test := range tests {
		d, err := NewDetectorDefaultConfig()
		require.NoError(t, err)
		d.baseline = test.baseline
		var kept []report.Finding
		for _, finding := range test.findings {
			if !d.ignore(finding) {
				kept = append(kept, finding)
			}
		}
		assert.Len(t, kept, test.expectCount)
	}
}
