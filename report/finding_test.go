package report

import (
	"encoding/json"
	"fmt"
	"testing"
	"unicode/utf8"

	"github.com/betterleaks/betterleaks/v2/sources"
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
					Match: Match{Full: "line containing secret", Value: "secret"},
				},
			}},
	}
	for _, test := range tests {
		for _, f := range test.findings {
			f.Redact(100)
			assert.Equal(t, "REDACTED", f.Match.Value)
			assert.Equal(t, "line containing REDACTED", f.Match.Full)
		}
	}
}

func TestRedact_ComponentSets(t *testing.T) {
	f := Finding{
		Match: Match{Full: "line containing secret", Value: "secret"},

		Analysis: Analysis{
			Reason:   "primary=secret",
			Identity: &AnalysisIdentity{ID: "comp-secret-1"},
			Metadata: map[string]any{"scope": "comp-secret-2"},
		},
		ComponentSets: []ComponentSet{
			{
				Analysis: Analysis{
					Debug: map[string]any{"echo": "comp-secret-2"},
				},
				Components: []*ComponentFinding{
					{
						RuleID: "rule-a", Match: Match{Value: "comp-secret-1", Full: "match comp-secret-1 here", Captures: map[string]string{"token": "comp-secret-1", "label": "safe"}}, Line: "line comp-secret-1 here",
					},
					{RuleID: "rule-b", Match: Match{Value: "comp-secret-2", Full: "match comp-secret-2 here"}},
				},
			},
		},
	}
	f.Redact(100)
	assert.Equal(t, "REDACTED", f.Match.Value)
	assert.Equal(t, "REDACTED", f.ComponentSets[0].Components[0].Match.Value)
	assert.Equal(t, "line REDACTED here", f.ComponentSets[0].Components[0].Line)
	assert.Equal(t, "match REDACTED here", f.ComponentSets[0].Components[0].Match.Full)
	assert.Equal(t, "REDACTED", f.ComponentSets[0].Components[0].Match.Captures["token"])
	assert.Equal(t, "REDACTED", f.ComponentSets[0].Components[0].Match.Captures["label"])
	assert.Equal(t, "REDACTED", f.ComponentSets[0].Components[1].Match.Value)
	assert.Equal(t, "match REDACTED here", f.ComponentSets[0].Components[1].Match.Full)
	assert.Equal(t, "primary=[redacted]", f.Analysis.Reason)
	assert.Equal(t, "[redacted]", f.Analysis.Metadata["scope"])
	require.NotNil(t, f.Analysis.Identity)
	assert.Equal(t, "[redacted]", f.Analysis.Identity.ID)
	assert.Equal(t, "[redacted]", f.ComponentSets[0].Analysis.Debug["echo"])
}

func TestRedact_SharedPointerDedup(t *testing.T) {
	// When the same ComponentFinding pointer appears in multiple sets (Cartesian product),
	// partial redaction (percent < 100) must only mask the secret once.
	shared := &ComponentFinding{
		RuleID: "rule-a", Match: Match{Value: "abcdefghij", Full: "found abcdefghij here", Captures: map[string]string{"token": "abcdefghij"}}, Line: "line abcdefghij here",
	}
	f := Finding{
		Match: Match{Full: "primary", Value: "primary"},
		ComponentSets: []ComponentSet{
			{Components: []*ComponentFinding{shared}},
			{Components: []*ComponentFinding{shared}},
		},
	}
	f.Redact(75)
	// 75% mask on 10-char secret: RoundToEven(10 * 25/100) = 2 chars kept → "ab..."
	assert.Equal(t, "ab...", shared.Match.Value)
	assert.Equal(t, "line ab... here", shared.Line)
	assert.Equal(t, "found ab... here", shared.Match.Full)
	assert.Equal(t, "ab...", shared.Match.Captures["token"])
}

func TestMask(t *testing.T) {

	tests := map[string]struct {
		finding Finding
		percent uint
		expect  Finding
	}{
		"normal secret": {
			finding: Finding{Match: Match{Full: "line containing secret", Value: "secret"}},
			expect:  Finding{Match: Match{Full: "line containing se...", Value: "se..."}},
			percent: 75,
		},
		"empty secret": {
			finding: Finding{Match: Match{Full: "line containing", Value: ""}},
			expect:  Finding{Match: Match{Full: "line containing", Value: ""}},
			percent: 75,
		},
		"short secret": {
			finding: Finding{Match: Match{Full: "line containing", Value: "ss"}},
			expect:  Finding{Match: Match{Full: "line containing", Value: "..."}},
			percent: 75,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			f := test.finding
			e := test.expect
			f.Redact(test.percent)
			assert.Equal(t, e.Match.Value, f.Match.Value)
			assert.Equal(t, e.Match.Full, f.Match.Full)
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
	rf := &ComponentFinding{RuleID: "rule-a", Match: Match{Value: "secret-a"}, Location: Location{StartLine: 1}}
	f := &Finding{}
	f.BuildComponentSets([]*ComponentFinding{rf}, 100)

	require.Len(t, f.ComponentSets, 1)
	require.Len(t, f.ComponentSets[0].Components, 1)
	assert.Equal(t, "rule-a", f.ComponentSets[0].Components[0].RuleID)
	assert.Equal(t, "secret-a", f.ComponentSets[0].Components[0].Match.Value)
}

func TestBuildComponentSets_MultiRuleMultiFinding(t *testing.T) {
	reqs := []*ComponentFinding{
		{RuleID: "rule-a", Match: Match{Value: "a1"}, Location: Location{StartLine: 1}},
		{RuleID: "rule-a", Match: Match{Value: "a2"}, Location: Location{StartLine: 2}},
		{RuleID: "rule-b", Match: Match{Value: "b1"}, Location: Location{StartLine: 3}},
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
		f.ComponentSets[0].Components[0].Match.Value: true,
		f.ComponentSets[1].Components[0].Match.Value: true,
	}
	assert.True(t, secrets["a1"])
	assert.True(t, secrets["a2"])
}

func TestBuildComponentSets_MaxCap(t *testing.T) {
	// 3 × 3 = 9 sets, cap at 5
	reqs := []*ComponentFinding{
		{RuleID: "r1", Match: Match{Value: "s1"}},
		{RuleID: "r1", Match: Match{Value: "s2"}},
		{RuleID: "r1", Match: Match{Value: "s3"}},
		{RuleID: "r2", Match: Match{Value: "t1"}},
		{RuleID: "r2", Match: Match{Value: "t2"}},
		{RuleID: "r2", Match: Match{Value: "t3"}},
	}
	f := &Finding{}
	f.BuildComponentSets(reqs, 5)
	assert.Len(t, f.ComponentSets, 5)
}

func TestBuildComponentSets_JSONSerialization(t *testing.T) {
	reqs := []*ComponentFinding{
		{RuleID: "aws-secret", Match: Match{Value: "wJalrXUtnFEMI"}, Location: Location{StartLine: 10}},
		{RuleID: "aws-region", Optional: true, Match: Match{Value: "us-east-1"}, Location: Location{StartLine: 11}},
	}
	f := &Finding{
		RuleID: "aws-access-key",
		Match:  Match{Value: "AKIAIOSFODNN7EXAMPLE"},
	}
	f.BuildComponentSets(reqs, 100)
	f.ComponentSets[0].Analysis = Analysis{
		Status: ValidationStatusValid,
		Reason: "The component set was accepted.",
	}

	data, err := json.Marshal(f)
	require.NoError(t, err)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(data, &parsed))

	sets, ok := parsed["component_sets"]
	require.True(t, ok, "componentSets should be present in JSON")
	setSlice, ok := sets.([]any)
	require.True(t, ok)
	require.Len(t, setSlice, 1)

	set := setSlice[0].(map[string]any)
	assert.Equal(t, map[string]any{
		"status": "valid",
		"reason": "The component set was accepted.",
	}, set["analysis"])
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
		Match: Match{Full: "https://user:pass@host.", Value: "pass", Captures: map[string]string{
			"host":     "host.",
			"password": "pass",
			"scheme":   "https",
			"uri":      "https://user:pass@host.",
			"username": "user",
		}},
		Location: Location{
			Path:        "sources/scm/clone.go",
			StartLine:   189,
			EndLine:     189,
			StartColumn: 56,
			EndColumn:   78,
		},
		Attributes: map[string]string{"resource": "fs.content"},
		Analysis:   Analysis{Severity: SeverityHigh, Identity: &AnalysisIdentity{ID: "user-1", Username: "octocat"}, Capabilities: []Capability{CapabilityRead, CapabilityManageUsers}, Metadata: map[string]any{"permissions": []any{"read_job"}}, Status: ValidationStatusValid, Reason: "The provider accepted the credential."},
		Tags:       []string{},
	}

	data, err := json.Marshal(f)
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(data, &got))
	assert.Equal(t, "generic-credential-uri", got["rule_id"])
	assert.Equal(t, "low", got["confidence"])
	assert.Equal(t, map[string]any{
		"path":         "sources/scm/clone.go",
		"start_line":   float64(189),
		"end_line":     float64(189),
		"start_column": float64(56),
		"end_column":   float64(78),
	}, got["location"])
	assert.Equal(t, map[string]any{
		"status":       "valid",
		"reason":       "The provider accepted the credential.",
		"severity":     "high",
		"identity":     map[string]any{"id": "user-1", "username": "octocat"},
		"capabilities": []any{"read", "manage_users"},
		"metadata":     map[string]any{"permissions": []any{"read_job"}},
	}, got["analysis"])
	assert.NotContains(t, got["attributes"], "confidence")
	assert.NotContains(t, got, "validation")
	assert.NotContains(t, got, "secret")
	assert.NotContains(t, got, "captureGroups")
	assert.Equal(t, f.Match.Full, got["match"].(map[string]any)["full"])
	assert.Equal(t, f.Match.Value, got["match"].(map[string]any)["value"])
	assert.NotContains(t, got["attributes"], "path")
	assert.NotContains(t, got, "StartLine")
	assert.NotContains(t, got, "ValidationStatus")

	var roundTrip Finding
	require.NoError(t, json.Unmarshal(data, &roundTrip))
	assert.Equal(t, f, roundTrip)
}

func TestFindingJSONOmitsInternalAttributes(t *testing.T) {
	f := Finding{
		Location: Location{Path: "secrets.txt"},
		Attributes: map[string]string{
			sources.AttrFSFirstFragment: "true",
		},
	}

	data, err := json.Marshal(f)
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(data, &got))
	assert.NotContains(t, got, "attributes")
	assert.Equal(t, map[string]any{"path": "secrets.txt"}, got["location"])
	assert.Equal(t, "true", f.Attributes[sources.AttrFSFirstFragment], "marshaling must not mutate the finding")
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
		Match: Match{Value: "supersecret", Full: "key=supersecret", Captures: map[string]string{
			"token": "supersecret",
			"user":  "alice",
		}},
		Line: "api key=supersecret here",
	}
	f.Redact(100)

	if f.Match.Captures["token"] != "REDACTED" {
		t.Errorf("capture group holding the secret must be redacted, got %q", f.Match.Captures["token"])
	}
	if f.Match.Captures["user"] != "REDACTED" {
		t.Errorf("all captures should be masked, got %q", f.Match.Captures["user"])
	}
}

func TestRedactPartiallyMasksCaptureGroups(t *testing.T) {
	f := Finding{
		Match: Match{Value: "abcdefghij", Captures: map[string]string{"t": "abcdefghij"}},
	}
	f.Redact(50)
	if want := MaskSecret("abcdefghij", 50); f.Match.Captures["t"] != want {
		t.Errorf("capture group should be partially masked to %q, got %q", want, f.Match.Captures["t"])
	}
}

func TestRedactedCopyDoesNotMutateOriginal(t *testing.T) {
	component := &ComponentFinding{
		Match: Match{Full: "component-secret", Value: "component-secret", Captures: map[string]string{"token": "component-secret"}},
	}
	original := Finding{
		Match:         Match{Full: "primary-secret", Value: "primary-secret", Captures: map[string]string{"token": "primary-secret"}},
		ComponentSets: []ComponentSet{{Components: []*ComponentFinding{component}}},
	}

	redacted := original.RedactedCopy(100)

	require.Equal(t, "REDACTED", redacted.Match.Value)
	require.Equal(t, "REDACTED", redacted.Match.Captures["token"])
	require.Equal(t, "REDACTED", redacted.ComponentSets[0].Components[0].Match.Value)
	require.Equal(t, "primary-secret", original.Match.Value)
	require.Equal(t, "primary-secret", original.Match.Captures["token"])
	require.Equal(t, "component-secret", component.Match.Value)
	require.Equal(t, "component-secret", component.Match.Captures["token"])
}

func TestRedactedCopySanitizesValidation(t *testing.T) {
	for _, percent := range []uint{50, 100} {
		primary, component := "test-token", "test-token-companion"
		validation := Analysis{
			Status: ValidationStatusValid,
			Reason: primary + " " + component,
			Metadata: map[string]any{
				"req_url":  "https://example.invalid/?token=" + primary,
				"req_body": component,
				"resp_body": []any{map[string]any{
					component: []string{primary, component},
				}},
				"headers": map[string]string{"echo": component},
				"status":  200,
				"empty":   "",
			},
		}
		original := Finding{
			Match:    Match{Value: primary},
			Analysis: validation,
			ComponentSets: []ComponentSet{{
				Analysis:   validation,
				Components: []*ComponentFinding{{Match: Match{Value: component}}},
			}},
		}
		before, err := json.Marshal(original)
		require.NoError(t, err)
		redacted := original.RedactedCopy(percent)
		encoded, err := json.Marshal(redacted)
		require.NoError(t, err)
		if percent == 100 {
			assert.NotContains(t, string(encoded), primary)
			assert.NotContains(t, string(encoded), component)
		}
		for _, got := range []Analysis{redacted.Analysis, redacted.ComponentSets[0].Analysis} {
			encoded, err := json.Marshal(got)
			require.NoError(t, err)
			assert.NotContains(t, string(encoded), primary)
			assert.NotContains(t, string(encoded), component)
			assert.Equal(t, ValidationStatusValid, got.Status)
			assert.Equal(t, "[redacted] [redacted]", got.Reason)
			assert.Equal(t, "[redacted]", got.Metadata["req_body"])
			assert.Equal(t, 200, got.Metadata["status"])
			assert.NotContains(t, got.Metadata, "empty")
		}
		after, err := json.Marshal(original)
		require.NoError(t, err)
		assert.Equal(t, string(before), string(after), "redaction must not mutate shared results")
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

func TestRedactedCopyMasksCompanionValuesAcrossMatches(t *testing.T) {
	const primary, companion = "test-token", "test-token-companion"
	shared := &ComponentFinding{Match: Match{Full: primary + " " + companion, Value: companion, Captures: map[string]string{"both": primary + " " + companion}}}
	finding := Finding{
		Match:         Match{Full: primary + " " + companion, Value: primary, Captures: map[string]string{"companion": companion}},
		MatchContext:  primary + " " + companion,
		ComponentSets: []ComponentSet{{Components: []*ComponentFinding{shared, nil}}, {Components: []*ComponentFinding{shared}}},
	}
	for _, percent := range []uint{50, 100} {
		redacted := finding.RedactedCopy(percent)
		want := "REDACTED"
		if percent < 100 {
			want = "test-..."
		}
		require.Equal(t, want, redacted.Match.Full)
		require.Equal(t, want, redacted.MatchContext)
		require.Equal(t, want, redacted.Match.Captures["companion"])
		require.Equal(t, want, redacted.ComponentSets[0].Components[0].Match.Value)
		require.Equal(t, want, redacted.ComponentSets[0].Components[0].Match.Captures["both"])

	}
	require.Equal(t, companion, shared.Match.Value)
	require.Equal(t, companion, finding.Match.Captures["companion"])
}

func TestPathOnlyRedactionPreservesEmptyValue(t *testing.T) {
	finding := Finding{Match: Match{Full: "file detected: service.env"}, Location: Location{Path: "service.env"}}
	require.Equal(t, finding, finding.RedactedCopy(100))
	data, err := json.Marshal(finding)
	require.NoError(t, err)
	var wire map[string]any
	require.NoError(t, json.Unmarshal(data, &wire))
	require.Equal(t, map[string]any{"path": "service.env"}, wire["location"])
	require.NotContains(t, wire, "analysis")
}

func TestExprAttributesUseCanonicalPathWithoutMutatingFinding(t *testing.T) {
	f := Finding{Location: Location{Path: "current.env"}, Attributes: map[string]string{"path": "stale.env", "application": "service"}}
	attrs := f.ExprAttributes()
	require.Equal(t, "current.env", attrs["path"])
	attrs["application"] = "changed"
	require.Equal(t, "service", f.Attributes["application"])
	f.SetAttr(sources.AttrPath, "new.env")
	require.Equal(t, "new.env", f.Location.Path)
	require.NotContains(t, f.Attributes, sources.AttrPath)
}

func TestRedactedCopySanitizesSourceAndCaptureMaterial(t *testing.T) {
	primary, secondary, companion := "private-primary-value", "private-secondary-value", "private-component-value"
	original := Finding{
		RuleID: "rule-" + primary, Description: secondary, Confidence: "high",
		Match:      Match{Full: primary, Value: primary, Captures: map[string]string{"secondary": secondary}},
		Attributes: map[string]string{"git.message": "fix " + primary + "\n" + secondary, companion: secondary},
		Location:   Location{Path: primary + ".env"}, Tags: []string{secondary}, MatchContext: companion,
		ComponentSets: []ComponentSet{{Components: []*ComponentFinding{{RuleID: "component", Match: Match{Value: companion, Captures: map[string]string{"secondary": secondary}}, Location: Location{Path: secondary}}}}},
		Analysis:      Analysis{Status: ValidationStatusValid, StatusReason: secondary, StatusMetadata: map[string]any{"echo": primary}, Metadata: map[string]any{secondary: []any{companion}}},
	}
	redacted := original.RedactedCopy(100)
	data, err := json.Marshal(redacted)
	require.NoError(t, err)
	for _, value := range []string{primary, secondary, companion} {
		require.NotContains(t, string(data), value)
	}
	require.Equal(t, "fix "+primary+"\n"+secondary, original.Attributes["git.message"])
	require.Equal(t, secondary, original.Tags[0])
	require.Equal(t, secondary, original.Match.Captures["secondary"])
	require.Equal(t, primary, original.Analysis.StatusMetadata["echo"])
	require.Equal(t, secondary, original.ComponentSets[0].Components[0].Location.Path)
}

func TestComponentSetCapAndTruncation(t *testing.T) {
	var components []*ComponentFinding
	for i := 0; i < 100; i++ {
		components = append(components, &ComponentFinding{RuleID: "part", Match: Match{Value: fmt.Sprint(i)}})
	}
	var finding Finding
	finding.BuildComponentSets(components, 100)
	require.Len(t, finding.ComponentSets, 100)
	require.False(t, finding.ComponentSetsTruncated)
	components = append(components, &ComponentFinding{RuleID: "part", Match: Match{Value: "last"}})
	finding.BuildComponentSets(components, 1000)
	require.Len(t, finding.ComponentSets, 100)
	require.True(t, finding.ComponentSetsTruncated)
	finding.BuildComponentSets(nil, 100)
	require.Empty(t, finding.ComponentSets)
	require.False(t, finding.ComponentSetsTruncated)
}
