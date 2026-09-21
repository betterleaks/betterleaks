package scan

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildComponentSets_Empty(t *testing.T) {
	f := &report.Finding{}
	f.ComponentSets, f.ComponentSetsTruncated = buildComponentSets(nil, 100)
	assert.Nil(t, f.ComponentSets)
}

func TestBuildComponentSets_SingleRuleSingleFinding(t *testing.T) {
	rf := report.ComponentFinding{RuleID: "rule-a", Match: report.Match{Value: "secret-a"}, Location: report.Location{StartLine: 1}}
	f := &report.Finding{}
	f.ComponentSets, f.ComponentSetsTruncated = buildComponentSets([]report.ComponentFinding{rf}, 100)

	require.Len(t, f.ComponentSets, 1)
	require.Len(t, f.ComponentSets[0].Components, 1)
	assert.Equal(t, "rule-a", f.ComponentSets[0].Components[0].RuleID)
	assert.Equal(t, "secret-a", f.ComponentSets[0].Components[0].Match.Value)
}

func TestBuildComponentSets_MultiRuleMultiFinding(t *testing.T) {
	reqs := []report.ComponentFinding{
		{RuleID: "rule-a", Match: report.Match{Value: "a1"}, Location: report.Location{StartLine: 1}},
		{RuleID: "rule-a", Match: report.Match{Value: "a2"}, Location: report.Location{StartLine: 2}},
		{RuleID: "rule-b", Match: report.Match{Value: "b1"}, Location: report.Location{StartLine: 3}},
	}
	f := &report.Finding{}
	f.ComponentSets, f.ComponentSetsTruncated = buildComponentSets(reqs, 100)

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
	reqs := []report.ComponentFinding{
		{RuleID: "r1", Match: report.Match{Value: "s1"}},
		{RuleID: "r1", Match: report.Match{Value: "s2"}},
		{RuleID: "r1", Match: report.Match{Value: "s3"}},
		{RuleID: "r2", Match: report.Match{Value: "t1"}},
		{RuleID: "r2", Match: report.Match{Value: "t2"}},
		{RuleID: "r2", Match: report.Match{Value: "t3"}},
	}
	f := &report.Finding{}
	f.ComponentSets, f.ComponentSetsTruncated = buildComponentSets(reqs, 5)
	assert.Len(t, f.ComponentSets, 5)
}

func TestBuildComponentSets_JSONSerialization(t *testing.T) {
	reqs := []report.ComponentFinding{
		{RuleID: "aws-secret", Match: report.Match{Value: "wJalrXUtnFEMI"}, Location: report.Location{StartLine: 10}},
		{RuleID: "aws-region", Optional: true, Match: report.Match{Value: "us-east-1"}, Location: report.Location{StartLine: 11}},
	}
	f := &report.Finding{
		RuleID: "aws-access-key",
		Match:  report.Match{Value: "AKIAIOSFODNN7EXAMPLE"},
	}
	f.ComponentSets, f.ComponentSetsTruncated = buildComponentSets(reqs, 100)
	f.ComponentSets[0].Analysis = report.Analysis{
		Status:   report.ValidationStatusValid,
		Severity: report.SeverityHigh,
		Reason:   "The component set was accepted.",
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
		"status":   "valid",
		"severity": "high",
	}, set["analysis"])
	components := set["components"].([]any)
	require.Len(t, components, 2)
	assert.NotContains(t, components[0].(map[string]any), "optional")
	assert.Equal(t, true, components[1].(map[string]any)["optional"])
	assert.Contains(t, components[0].(map[string]any), "location")
}

func TestComponentSetCapAndTruncation(t *testing.T) {
	var components []report.ComponentFinding
	for i := range 100 {
		components = append(components, report.ComponentFinding{RuleID: "part", Match: report.Match{Value: fmt.Sprint(i)}})
	}
	var finding report.Finding
	finding.ComponentSets, finding.ComponentSetsTruncated = buildComponentSets(components, 100)
	require.Len(t, finding.ComponentSets, 100)
	require.False(t, finding.ComponentSetsTruncated)
	components = append(components, report.ComponentFinding{RuleID: "part", Match: report.Match{Value: "last"}})
	finding.ComponentSets, finding.ComponentSetsTruncated = buildComponentSets(components, 1000)
	require.Len(t, finding.ComponentSets, 100)
	require.True(t, finding.ComponentSetsTruncated)
	finding.ComponentSets, finding.ComponentSetsTruncated = buildComponentSets(nil, 100)
	require.Empty(t, finding.ComponentSets)
	require.False(t, finding.ComponentSetsTruncated)
}

func TestScannerFindingsOwnComponentCaptures(t *testing.T) {
	cfg := &config.Config{Rules: []config.Rule{
		{ID: "primary", Regex: `primary-[a-z]+`, Components: []config.Component{{RuleID: "account"}, {RuleID: "region"}}},
		{ID: "account", Regex: `account=(?P<account>[a-z]+)`, SkipReport: true},
		{ID: "region", Regex: `region-[a-z]+`, SkipReport: true},
	}}
	const raw = "primary-first\nprimary-second\naccount=acme\nregion-east\nregion-west"
	for _, method := range []string{"ScanString", "Scan", "Run"} {
		t.Run(method, func(t *testing.T) {
			scanner := mustNew(t, cfg)
			var findings []report.Finding
			accept := func(finding report.Finding) error {
				require.Len(t, finding.ComponentSets, 2)
				if len(findings) == 0 {
					finding.ComponentSets[0].Components[0].Match.Captures["account"] = "changed"
				}
				findings = append(findings, finding)
				return nil
			}
			switch method {
			case "ScanString":
				for _, finding := range scanner.ScanString(raw) {
					require.NoError(t, accept(finding))
				}
			case "Scan":
				_, err := scanner.Scan(t.Context(), &sources.Reader{Content: strings.NewReader(raw)}, accept)
				require.NoError(t, err)
			case "Run":
				for result := range scanner.Run(t.Context(), &sources.Reader{Content: strings.NewReader(raw)}) {
					require.NoError(t, result.Err)
					require.NoError(t, accept(result.Finding))
				}
			}
			require.Len(t, findings, 2)
			for i, finding := range findings {
				for j, set := range finding.ComponentSets {
					want := "acme"
					if i == 0 && j == 0 {
						want = "changed"
					}
					assert.Equal(t, want, set.Components[0].Match.Captures["account"], "finding %d set %d", i, j)
				}
			}
		})
	}
}

func BenchmarkComponentSets(b *testing.B) {
	for _, captures := range []bool{false, true} {
		b.Run(fmt.Sprintf("captures=%t", captures), func(b *testing.B) {
			var candidates []report.ComponentFinding
			for group := range 3 {
				for value := range 10 {
					match := report.Match{Value: fmt.Sprint(value)}
					if captures {
						match.Captures = map[string]string{"value": match.Value}
					}
					candidates = append(candidates, report.ComponentFinding{RuleID: fmt.Sprint(group), Match: match})
				}
			}
			b.ReportAllocs()
			for b.Loop() {
				sets, truncated := buildComponentSets(candidates, 100)
				if len(sets) != 100 || !truncated {
					b.Fatal("expected 100 retained combinations and truncation")
				}
			}
		})
	}
}

func TestComponentProximityUsesOriginalFragmentOffsets(t *testing.T) {
	cfg := &config.Config{Rules: []config.Rule{
		{ID: "primary-a", Regex: `PRIMARYA`, Components: []config.Component{{RuleID: "component", Within: "10C"}}},
		{ID: "primary-b", Regex: `PRIMARYB`, Components: []config.Component{{RuleID: "component", Within: "10C"}}},
		{ID: "component", Regex: `COMPONENT[AB]`, SkipReport: true},
	}}
	scanner := mustNew(t, cfg, WithMaxDecodeDepth(2))
	for depth := range 3 {
		t.Run(fmt.Sprintf("decode_depth=%d", depth), func(t *testing.T) {
			lines := []string{"PRIMARYA COMPONENTA", strings.Repeat(".", 80), "PRIMARYB COMPONENTB", ""}
			for range depth {
				lines[0] = base64.StdEncoding.EncodeToString([]byte(lines[0]))
				lines[2] = base64.StdEncoding.EncodeToString([]byte(lines[2]))
			}
			findings := scanner.detectFragment(t.Context(), sources.Fragment{Raw: strings.Join(lines, "\n"), StartLine: 41})
			require.Len(t, findings, 2)
			for i, finding := range findings {
				require.Len(t, finding.ComponentSets, 1)
				component := finding.ComponentSets[0].Components[0]
				assert.Equal(t, 41+i*2, finding.Location.StartLine)
				assert.Equal(t, finding.Location.StartLine, component.Location.StartLine)
				assert.Equal(t, fmt.Sprintf("COMPONENT%c", 'A'+i), component.Match.Value)
			}
		})
	}
}

func TestExprAttributesUseCanonicalPathWithoutMutatingFinding(t *testing.T) {
	f := report.Finding{Location: report.Location{Path: "current.env"}, Attributes: map[string]string{"path": "stale.env", "application": "service"}}
	attrs := exprAttributes(f)
	require.Equal(t, "current.env", attrs["path"])
	attrs["application"] = "changed"
	require.Equal(t, "service", f.Attributes["application"])
	f.SetAttr(sources.AttrPath, "new.env")
	require.Equal(t, "new.env", f.Location.Path)
	require.NotContains(t, f.Attributes, sources.AttrPath)
}
