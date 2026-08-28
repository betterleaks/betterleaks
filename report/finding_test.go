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
	rf := &ComponentFinding{RuleID: "rule-a", Secret: "secret-a", Location: Location{StartLine: 1}}
	f := &Finding{}
	f.BuildComponentSets([]*ComponentFinding{rf}, 100)

	require.Len(t, f.ComponentSets, 1)
	require.Len(t, f.ComponentSets[0].Components, 1)
	assert.Equal(t, "rule-a", f.ComponentSets[0].Components[0].RuleID)
	assert.Equal(t, "secret-a", f.ComponentSets[0].Components[0].Secret)
}

func TestBuildComponentSets_MultiRuleMultiFinding(t *testing.T) {
	reqs := []*ComponentFinding{
		{RuleID: "rule-a", Secret: "a1", Location: Location{StartLine: 1}},
		{RuleID: "rule-a", Secret: "a2", Location: Location{StartLine: 2}},
		{RuleID: "rule-b", Secret: "b1", Location: Location{StartLine: 3}},
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
		{RuleID: "aws-secret", Secret: "wJalrXUtnFEMI", Location: Location{StartLine: 10}},
		{RuleID: "aws-region", Optional: true, Secret: "us-east-1", Location: Location{StartLine: 11}},
	}
	f := &Finding{
		RuleID: "aws-access-key",
		Secret: "AKIAIOSFODNN7EXAMPLE",
	}
	f.BuildComponentSets(reqs, 100)
	f.ComponentSets[0].Validation = Validation{
		Status: ValidationStatusValid,
		Reason: "The component set was accepted.",
	}

	data, err := json.Marshal(f)
	require.NoError(t, err)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(data, &parsed))

	sets, ok := parsed["componentSets"]
	require.True(t, ok, "componentSets should be present in JSON")
	setSlice, ok := sets.([]any)
	require.True(t, ok)
	require.Len(t, setSlice, 1)

	set := setSlice[0].(map[string]any)
	assert.Equal(t, map[string]any{
		"status": "valid",
		"reason": "The component set was accepted.",
	}, set["validation"])
	components := set["components"].([]any)
	require.Len(t, components, 2)
	assert.NotContains(t, components[0].(map[string]any), "optional")
	assert.Equal(t, true, components[1].(map[string]any)["optional"])
	assert.Contains(t, components[0].(map[string]any), "location")
}

func TestFindingJSONSchema(t *testing.T) {
	f := Finding{
		RuleID:      "generic-credential-uri",
		Description: "Detected a password embedded in a service connection URI.",
		Confidence:  "low",
		Match:       "https://user:pass@host.",
		Secret:      "pass",
		CaptureGroups: map[string]string{
			"host":     "host.",
			"password": "pass",
			"scheme":   "https",
			"uri":      "https://user:pass@host.",
			"username": "user",
		},
		Location: Location{
			StartLine:   189,
			EndLine:     189,
			StartColumn: 56,
			EndColumn:   78,
		},
		Attributes: map[string]string{"path": "sources/scm/clone.go", "resource": "fs.content"},
		Validation: Validation{
			Status:   ValidationStatusValid,
			Reason:   "The provider accepted the credential.",
			Metadata: map[string]any{"account": "example"},
		},
		Tags: []string{},
	}

	data, err := json.Marshal(f)
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(data, &got))
	assert.Equal(t, "generic-credential-uri", got["ruleID"])
	assert.Equal(t, "low", got["confidence"])
	assert.Equal(t, map[string]any{
		"startLine":   float64(189),
		"endLine":     float64(189),
		"startColumn": float64(56),
		"endColumn":   float64(78),
	}, got["location"])
	assert.Equal(t, map[string]any{
		"status":   "valid",
		"reason":   "The provider accepted the credential.",
		"metadata": map[string]any{"account": "example"},
	}, got["validation"])
	assert.NotContains(t, got["attributes"], "confidence")
	assert.NotContains(t, got, "StartLine")
	assert.NotContains(t, got, "ValidationStatus")

	var roundTrip Finding
	require.NoError(t, json.Unmarshal(data, &roundTrip))
	assert.Equal(t, f, roundTrip)
}

func TestSetAttributesPromotesConfidence(t *testing.T) {
	attrs := map[string]string{
		sources.AttrPath: "secrets.txt",
		"confidence":     "high",
	}
	var f Finding
	f.SetAttributes(attrs)

	assert.Equal(t, "high", f.Confidence)
	assert.Equal(t, "high", f.Attr("confidence"))
	assert.Equal(t, "secrets.txt", f.Attr(sources.AttrPath))
	assert.NotContains(t, f.Attributes, "confidence")
	assert.Contains(t, attrs, "confidence", "the caller's map must not be mutated")
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

func TestRedactedCopyDoesNotMutateOriginal(t *testing.T) {
	component := &ComponentFinding{
		Match:         "component-secret",
		Secret:        "component-secret",
		CaptureGroups: map[string]string{"token": "component-secret"},
	}
	original := Finding{
		Match:         "primary-secret",
		Secret:        "primary-secret",
		CaptureGroups: map[string]string{"token": "primary-secret"},
		ComponentSets: []ComponentSet{{Components: []*ComponentFinding{component}}},
	}

	redacted := original.RedactedCopy(100)

	require.Equal(t, "REDACTED", redacted.Secret)
	require.Equal(t, "REDACTED", redacted.CaptureGroups["token"])
	require.Equal(t, "REDACTED", redacted.ComponentSets[0].Components[0].Secret)
	require.Equal(t, "primary-secret", original.Secret)
	require.Equal(t, "primary-secret", original.CaptureGroups["token"])
	require.Equal(t, "component-secret", component.Secret)
	require.Equal(t, "component-secret", component.CaptureGroups["token"])
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
