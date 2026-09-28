package scan

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildComponentSets(t *testing.T) {
	for _, tc := range []struct {
		name        string
		groups      []int
		limit, want int
		truncated   bool
	}{
		{"empty", nil, 100, 0, false},
		{"single", []int{1}, 100, 1, false},
		{"cartesian product", []int{2, 1}, 100, 2, false},
		{"requested cap", []int{3, 3}, 5, 5, true},
		{"exact cap", []int{100}, 100, 100, false},
		{"hard cap", []int{101}, 1000, 100, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var input []report.ComponentFinding
			for group, count := range tc.groups {
				for value := range count {
					input = append(input, report.ComponentFinding{
						RuleID: fmt.Sprint(group), Match: report.Match{Value: fmt.Sprint(value)},
						Location: report.Location{StartLine: value + 1},
					})
				}
			}
			sets, truncated := buildComponentSets(input, tc.limit)
			require.Len(t, sets, tc.want)
			require.Equal(t, tc.truncated, truncated)
			if tc.want == 0 {
				require.Nil(t, sets)
			}
			seen := make(map[string]bool)
			for _, set := range sets {
				require.Len(t, set.Components, len(tc.groups), "one component per rule")
				var values []string
				for group, component := range set.Components {
					require.Equal(t, fmt.Sprint(group), component.RuleID)
					require.Contains(t, input, component, "retain the original match and location")
					values = append(values, component.Match.Value)
				}
				key := strings.Join(values, ":")
				require.False(t, seen[key], "duplicate combination %s", key)
				seen[key] = true
			}
		})
	}
}

func TestBuildComponentSetsOwnEncodings(t *testing.T) {
	input := []report.ComponentFinding{
		{RuleID: "account", Encodings: []string{"base64"}, DecodeDepth: 1},
		{RuleID: "region", Match: report.Match{Value: "east"}},
		{RuleID: "region", Match: report.Match{Value: "west"}},
	}
	sets, _ := buildComponentSets(input, 100)
	require.Len(t, sets, 2)
	sets[0].Components[0].Encodings[0] = "changed"
	assert.Equal(t, []string{"base64"}, sets[1].Components[0].Encodings)
	assert.Equal(t, []string{"base64"}, input[0].Encodings)
}

func TestScannerFindingsOwnComponentCaptures(t *testing.T) {
	cfg := &config.Config{Rules: []config.Rule{
		{ID: "primary", Regex: `primary-[a-z]+`, Components: []config.Component{{RuleID: "account"}, {RuleID: "region"}}},
		{ID: "account", Regex: `account=(?P<account>[a-z]+)`, SkipReport: true},
		{ID: "region", Regex: `region-[a-z]+`, SkipReport: true},
	}}
	const raw = "primary-first\nprimary-second\naccount=acme\nregion-east\nregion-west"
	for _, method := range []string{"ScanString", "Scan"} {
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
				assert.Equal(t, depth, finding.DecodeDepth)
				assert.Equal(t, depth, component.DecodeDepth)
				if depth > 0 {
					assert.Equal(t, []string{"base64"}, finding.Encodings)
					assert.Equal(t, []string{"base64"}, component.Encodings)
				} else {
					assert.Empty(t, finding.Encodings)
					assert.Empty(t, component.Encodings)
				}
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
