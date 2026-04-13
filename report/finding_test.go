package report

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/betterleaks/betterleaks/sources"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedact(t *testing.T) {
	tests := []struct {
		findings []Finding
		redact   bool
	}{
		{
			redact: true,
			findings: []Finding{
				{
					Match:  "line containing secret",
					Secret: "secret",
				},
			}},
	}
	for _, test := range tests {
		for _, f := range test.findings {
			f.Redact(100)
			assert.Equal(t, "REDACTED", f.Secret)
			assert.Equal(t, "line containing REDACTED", f.Match)
		}
	}
}

func TestRedact_RequiredSets(t *testing.T) {
	f := Finding{
		Match:  "line containing secret",
		Secret: "secret",
		RequiredSets: []RequiredSet{
			{
				Components: []*RequiredFinding{
					{RuleID: "rule-a", Secret: "comp-secret-1", Match: "match comp-secret-1 here"},
					{RuleID: "rule-b", Secret: "comp-secret-2", Match: "match comp-secret-2 here"},
				},
			},
		},
	}
	f.Redact(100)
	assert.Equal(t, "REDACTED", f.Secret)
	assert.Equal(t, "REDACTED", f.RequiredSets[0].Components[0].Secret)
	assert.Equal(t, "match REDACTED here", f.RequiredSets[0].Components[0].Match)
	assert.Equal(t, "REDACTED", f.RequiredSets[0].Components[1].Secret)
	assert.Equal(t, "match REDACTED here", f.RequiredSets[0].Components[1].Match)
}

func TestRedact_SharedPointerDedup(t *testing.T) {
	// When the same RequiredFinding pointer appears in multiple sets (Cartesian product),
	// partial redaction (percent < 100) must only mask the secret once.
	shared := &RequiredFinding{RuleID: "rule-a", Secret: "abcdefghij", Match: "found abcdefghij here"}
	f := Finding{
		Match:  "primary",
		Secret: "primary",
		RequiredSets: []RequiredSet{
			{Components: []*RequiredFinding{shared}},
			{Components: []*RequiredFinding{shared}},
		},
	}
	f.Redact(75)
	// 75% mask on 10-char secret: RoundToEven(10 * 25/100) = 2 chars kept → "ab..."
	assert.Equal(t, "ab...", shared.Secret)
	assert.Equal(t, "found ab... here", shared.Match)
}

func TestMask(t *testing.T) {

	tests := map[string]struct {
		finding Finding
		percent uint
		expect  Finding
	}{
		"normal secret": {
			finding: Finding{Match: "line containing secret", Secret: "secret"},
			expect:  Finding{Match: "line containing se...", Secret: "se..."},
			percent: 75,
		},
		"empty secret": {
			finding: Finding{Match: "line containing", Secret: ""},
			expect:  Finding{Match: "line containing", Secret: ""},
			percent: 75,
		},
		"short secret": {
			finding: Finding{Match: "line containing", Secret: "ss"},
			expect:  Finding{Match: "line containing", Secret: "..."},
			percent: 75,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			f := test.finding
			e := test.expect
			f.Redact(test.percent)
			assert.Equal(t, e.Secret, f.Secret)
			assert.Equal(t, e.Match, f.Match)
		})
	}
}

func TestMaskSecret(t *testing.T) {

	tests := map[string]struct {
		secret  string
		percent uint
		expect  string
	}{
		"normal masking":  {secret: "secret", percent: 75, expect: "se..."},
		"high masking":    {secret: "secret", percent: 90, expect: "s..."},
		"low masking":     {secret: "secret", percent: 10, expect: "secre..."},
		"invalid masking": {secret: "secret", percent: 1000, expect: "..."},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got := MaskSecret(test.secret, test.percent)
			assert.Equal(t, test.expect, got)
		})
	}
}

func TestBuildRequiredSets_Empty(t *testing.T) {
	f := &Finding{}
	f.BuildRequiredSets(nil, 100)
	assert.Nil(t, f.RequiredSets)
}

func TestBuildRequiredSets_SingleRuleSingleFinding(t *testing.T) {
	rf := &RequiredFinding{RuleID: "rule-a", Secret: "secret-a", StartLine: 1}
	f := &Finding{}
	f.BuildRequiredSets([]*RequiredFinding{rf}, 100)

	require.Len(t, f.RequiredSets, 1)
	require.Len(t, f.RequiredSets[0].Components, 1)
	assert.Equal(t, "rule-a", f.RequiredSets[0].Components[0].RuleID)
	assert.Equal(t, "secret-a", f.RequiredSets[0].Components[0].Secret)
}

func TestBuildRequiredSets_MultiRuleMultiFinding(t *testing.T) {
	reqs := []*RequiredFinding{
		{RuleID: "rule-a", Secret: "a1", StartLine: 1},
		{RuleID: "rule-a", Secret: "a2", StartLine: 2},
		{RuleID: "rule-b", Secret: "b1", StartLine: 3},
	}
	f := &Finding{}
	f.BuildRequiredSets(reqs, 100)

	// 2 values for rule-a × 1 value for rule-b = 2 sets
	require.Len(t, f.RequiredSets, 2)
	for _, set := range f.RequiredSets {
		require.Len(t, set.Components, 2, "each set should have one component per rule")
		assert.Equal(t, "rule-a", set.Components[0].RuleID)
		assert.Equal(t, "rule-b", set.Components[1].RuleID)
	}
	// Verify distinct secrets in rule-a position.
	secrets := map[string]bool{
		f.RequiredSets[0].Components[0].Secret: true,
		f.RequiredSets[1].Components[0].Secret: true,
	}
	assert.True(t, secrets["a1"])
	assert.True(t, secrets["a2"])
}

func TestBuildRequiredSets_MaxCap(t *testing.T) {
	// 3 × 3 = 9 sets, cap at 5
	reqs := []*RequiredFinding{
		{RuleID: "r1", Secret: "s1"},
		{RuleID: "r1", Secret: "s2"},
		{RuleID: "r1", Secret: "s3"},
		{RuleID: "r2", Secret: "t1"},
		{RuleID: "r2", Secret: "t2"},
		{RuleID: "r2", Secret: "t3"},
	}
	f := &Finding{}
	f.BuildRequiredSets(reqs, 5)
	assert.Len(t, f.RequiredSets, 5)
}

func TestBuildRequiredSets_JSONSerialization(t *testing.T) {
	reqs := []*RequiredFinding{
		{RuleID: "aws-secret", Secret: "wJalrXUtnFEMI", StartLine: 10},
		{RuleID: "aws-region", Secret: "us-east-1", StartLine: 11},
	}
	f := &Finding{
		RuleID: "aws-access-key",
		Secret: "AKIAIOSFODNN7EXAMPLE",
	}
	f.BuildRequiredSets(reqs, 100)

	data, err := json.Marshal(f)
	require.NoError(t, err)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(data, &parsed))

	sets, ok := parsed["RequiredSets"]
	require.True(t, ok, "RequiredSets should be present in JSON")
	setSlice, ok := sets.([]any)
	require.True(t, ok)
	require.Len(t, setSlice, 1)

	set := setSlice[0].(map[string]any)
	components := set["components"].([]any)
	require.Len(t, components, 2)
}

func TestFindingAttrFallsBackToDeprecatedFields(t *testing.T) {
	f := Finding{
		File:   "fallback.txt",
		Commit: "abc123",
		Author: "alice",
		Email:  "alice@example.com",
		Date:   "2026-04-13",
	}

	assert.Equal(t, "fallback.txt", f.Attr(sources.AttrPath))
	assert.Equal(t, "abc123", f.Attr(sources.AttrGitSHA))
	assert.Equal(t, "alice", f.Attr(sources.AttrGitAuthorName))
	assert.Equal(t, "alice@example.com", f.Attr(sources.AttrGitAuthorEmail))
	assert.Equal(t, "2026-04-13", f.Attr(sources.AttrGitDate))
}

func TestPrint_UsesAttributesForSourceMetadata(t *testing.T) {
	f := Finding{
		RuleID:      "test-rule",
		Entropy:     3.14,
		Line:        "token = secret-value",
		Match:       "secret-value",
		Secret:      "secret-value",
		StartLine:   12,
		Fingerprint: "commit123:path/to/file.txt:test-rule:12",
		Tags:        []string{"tag-a", "tag-b"},
		Attributes: map[string]string{
			sources.AttrPath:           "path/to/file.txt",
			sources.AttrGitSHA:         "commit123",
			sources.AttrGitAuthorName:  "alice",
			sources.AttrGitAuthorEmail: "alice@example.com",
			sources.AttrGitDate:        "2026-04-13",
		},
	}

	output := captureStdout(t, func() {
		f.Print(true, 0)
	})

	assert.Contains(t, output, "File:        path/to/file.txt")
	assert.Contains(t, output, "Line:        12")
	assert.Contains(t, output, "Commit:      commit123")
	assert.Contains(t, output, "Author:      alice")
	assert.Contains(t, output, "Email:       alice@example.com")
	assert.Contains(t, output, "Date:        2026-04-13")
	assert.Contains(t, output, "Fingerprint: commit123:path/to/file.txt:test-rule:12")
	assert.Contains(t, output, "Tags:        [tag-a tag-b]")
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	original := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)

	os.Stdout = w
	t.Cleanup(func() {
		os.Stdout = original
	})

	fn()
	require.NoError(t, w.Close())

	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	require.NoError(t, err)
	require.NoError(t, r.Close())

	os.Stdout = original

	return buf.String()
}
