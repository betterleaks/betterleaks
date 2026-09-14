package scan

import (
	"encoding/json"
	"fmt"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
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
		Status: report.ValidationStatusValid,
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

func TestComponentSetCapAndTruncation(t *testing.T) {
	var components []report.ComponentFinding
	for i := 0; i < 100; i++ {
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
