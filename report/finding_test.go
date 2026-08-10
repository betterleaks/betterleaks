package report

import (
	"encoding/json"
	"testing"
	"unicode/utf8"

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

func TestRedact_ComponentSets(t *testing.T) {
	f := Finding{
		Match:  "line containing secret",
		Secret: "secret",
		ComponentSets: []ComponentSet{
			{
				Components: []*ComponentFinding{
					{
						RuleID: "rule-a", Secret: "comp-secret-1", Line: "line comp-secret-1 here", Match: "match comp-secret-1 here",
						CaptureGroups: map[string]string{"token": "comp-secret-1", "label": "safe"},
					},
					{RuleID: "rule-b", Secret: "comp-secret-2", Match: "match comp-secret-2 here"},
				},
			},
		},
	}
	f.Redact(100)
	assert.Equal(t, "REDACTED", f.Secret)
	assert.Equal(t, "REDACTED", f.ComponentSets[0].Components[0].Secret)
	assert.Equal(t, "line REDACTED here", f.ComponentSets[0].Components[0].Line)
	assert.Equal(t, "match REDACTED here", f.ComponentSets[0].Components[0].Match)
	assert.Equal(t, "REDACTED", f.ComponentSets[0].Components[0].CaptureGroups["token"])
	assert.Equal(t, "safe", f.ComponentSets[0].Components[0].CaptureGroups["label"])
	assert.Equal(t, "REDACTED", f.ComponentSets[0].Components[1].Secret)
	assert.Equal(t, "match REDACTED here", f.ComponentSets[0].Components[1].Match)
}

func TestRedact_SharedPointerDedup(t *testing.T) {
	// When the same ComponentFinding pointer appears in multiple sets (Cartesian product),
	// partial redaction (percent < 100) must only mask the secret once.
	shared := &ComponentFinding{
		RuleID: "rule-a", Secret: "abcdefghij", Line: "line abcdefghij here", Match: "found abcdefghij here",
		CaptureGroups: map[string]string{"token": "abcdefghij"},
	}
	f := Finding{
		Match:  "primary",
		Secret: "primary",
		ComponentSets: []ComponentSet{
			{Components: []*ComponentFinding{shared}},
			{Components: []*ComponentFinding{shared}},
		},
	}
	f.Redact(75)
	// 75% mask on 10-char secret: RoundToEven(10 * 25/100) = 2 chars kept → "ab..."
	assert.Equal(t, "ab...", shared.Secret)
	assert.Equal(t, "line ab... here", shared.Line)
	assert.Equal(t, "found ab... here", shared.Match)
	assert.Equal(t, "ab...", shared.CaptureGroups["token"])
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

func TestBuildComponentSets_Empty(t *testing.T) {
	f := &Finding{}
	f.BuildComponentSets(nil, 100)
	assert.Nil(t, f.ComponentSets)
}

func TestBuildComponentSets_SingleRuleSingleFinding(t *testing.T) {
	rf := &ComponentFinding{RuleID: "rule-a", Secret: "secret-a", StartLine: 1}
	f := &Finding{}
	f.BuildComponentSets([]*ComponentFinding{rf}, 100)

	require.Len(t, f.ComponentSets, 1)
	require.Len(t, f.ComponentSets[0].Components, 1)
	assert.Equal(t, "rule-a", f.ComponentSets[0].Components[0].RuleID)
	assert.Equal(t, "secret-a", f.ComponentSets[0].Components[0].Secret)
}

func TestBuildComponentSets_MultiRuleMultiFinding(t *testing.T) {
	reqs := []*ComponentFinding{
		{RuleID: "rule-a", Secret: "a1", StartLine: 1},
		{RuleID: "rule-a", Secret: "a2", StartLine: 2},
		{RuleID: "rule-b", Secret: "b1", StartLine: 3},
	}
	f := &Finding{}
	f.BuildComponentSets(reqs, 100)

	// 2 values for rule-a × 1 value for rule-b = 2 sets
	require.Len(t, f.ComponentSets, 2)
	for _, set := range f.ComponentSets {
		require.Len(t, set.Components, 2, "each set should have one component per rule")
		assert.Equal(t, "rule-a", set.Components[0].RuleID)
		assert.Equal(t, "rule-b", set.Components[1].RuleID)
	}
	// Verify distinct secrets in rule-a position.
	secrets := map[string]bool{
		f.ComponentSets[0].Components[0].Secret: true,
		f.ComponentSets[1].Components[0].Secret: true,
	}
	assert.True(t, secrets["a1"])
	assert.True(t, secrets["a2"])
}

func TestBuildComponentSets_MaxCap(t *testing.T) {
	// 3 × 3 = 9 sets, cap at 5
	reqs := []*ComponentFinding{
		{RuleID: "r1", Secret: "s1"},
		{RuleID: "r1", Secret: "s2"},
		{RuleID: "r1", Secret: "s3"},
		{RuleID: "r2", Secret: "t1"},
		{RuleID: "r2", Secret: "t2"},
		{RuleID: "r2", Secret: "t3"},
	}
	f := &Finding{}
	f.BuildComponentSets(reqs, 5)
	assert.Len(t, f.ComponentSets, 5)
}

func TestBuildComponentSets_JSONSerialization(t *testing.T) {
	reqs := []*ComponentFinding{
		{RuleID: "aws-secret", Secret: "wJalrXUtnFEMI", StartLine: 10},
		{RuleID: "aws-region", Optional: true, Secret: "us-east-1", StartLine: 11},
	}
	f := &Finding{
		RuleID: "aws-access-key",
		Secret: "AKIAIOSFODNN7EXAMPLE",
	}
	f.BuildComponentSets(reqs, 100)

	data, err := json.Marshal(f)
	require.NoError(t, err)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(data, &parsed))

	sets, ok := parsed["ComponentSets"]
	require.True(t, ok, "ComponentSets should be present in JSON")
	assert.NotContains(t, parsed, "RequiredSets")
	setSlice, ok := sets.([]any)
	require.True(t, ok)
	require.Len(t, setSlice, 1)

	set := setSlice[0].(map[string]any)
	components := set["components"].([]any)
	require.Len(t, components, 2)
	assert.Equal(t, false, components[0].(map[string]any)["Optional"])
	assert.Equal(t, true, components[1].(map[string]any)["Optional"])
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

func TestRedactMasksCaptureGroups(t *testing.T) {
	f := Finding{
		Secret: "supersecret",
		Match:  "key=supersecret",
		Line:   "api key=supersecret here",
		CaptureGroups: map[string]string{
			"token": "supersecret",
			"user":  "alice",
		},
	}
	f.Redact(100)

	if f.CaptureGroups["token"] != "REDACTED" {
		t.Errorf("capture group holding the secret must be redacted, got %q", f.CaptureGroups["token"])
	}
	if f.CaptureGroups["user"] != "alice" {
		t.Errorf("non-secret capture group should be left intact, got %q", f.CaptureGroups["user"])
	}
}

func TestRedactPartiallyMasksCaptureGroups(t *testing.T) {
	f := Finding{
		Secret:        "abcdefghij",
		CaptureGroups: map[string]string{"t": "abcdefghij"},
	}
	f.Redact(50)
	if want := MaskSecret("abcdefghij", 50); f.CaptureGroups["t"] != want {
		t.Errorf("capture group should be partially masked to %q, got %q", want, f.CaptureGroups["t"])
	}
}

func TestMaskSecretMultibyteUTF8(t *testing.T) {
	secret := "日本語パスワード" // 8 runes, 24 bytes

	// At 70% the old byte-based slice cut at byte 7 (inside the 3rd rune),
	// producing invalid UTF-8. The rune-based mask keeps whole runes.
	got := MaskSecret(secret, 70)
	if !utf8.ValidString(got) {
		t.Fatalf("masked multi-byte secret is not valid UTF-8: %q", got)
	}
	if want := string([]rune(secret)[:2]) + "..."; got != want {
		t.Errorf("got %q want %q", got, want)
	}
}
