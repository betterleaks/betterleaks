package scan

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/regexp"
	"github.com/betterleaks/betterleaks/v2/regexp/re2"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/stretchr/testify/require"
)

func TestSpecificityUsesSourceRanges(t *testing.T) {
	for _, engine := range []regexp.Engine{regexp.Stdlib{}, re2.RE2{}} {
		t.Run(engine.Version(), func(t *testing.T) {
			t.Parallel()
			for _, tc := range []struct {
				name, raw, specific, generic string
				want                         []string
			}{
				{"generic starts earlier", "keys:\n child: VALUE", `VALUE`, `keys:\n child: (VALUE)`, []string{"specific"}},
				{"specific starts earlier", "provider:\n VALUE", `provider:\n (VALUE)`, `VALUE`, []string{"specific"}},
				{"separate occurrences on one line", "provider=VALUE other=VALUE", `provider=(VALUE)`, `other=(VALUE)`, []string{"specific", "generic"}},
				{"separate occurrences on different lines", "provider=VALUE\nother=VALUE", `provider=(VALUE)`, `other=(VALUE)`, []string{"specific", "generic"}},
				{"overlapping context with different values", "provider=FIRST other=VALUE", `provider=(FIRST) other=VALUE`, `other=(VALUE)`, []string{"specific", "generic"}},
				{"contained value", "provider=prefix-VALUE-suffix", `provider=(prefix-VALUE-suffix)`, `VALUE`, []string{"specific"}},
				{"percent prefix", "%70rovider=VALUE", `provider=(VALUE)`, `VALUE`, []string{"specific"}},
				{"percent identifier suffix", "prefix%31=VALUE", `prefix1=(VALUE)`, `VALUE`, []string{"specific"}},
				{"nested percent prefix", "%2570rovider=VALUE", `provider=(VALUE)`, `VALUE`, []string{"specific"}},
				{"percent prefix and separate value", "%70rovider=VALUE; other=VALUE", `provider=(VALUE)`, `VALUE`, []string{"generic", "specific"}},
				{"plain value between escapes", "%70rovider=VALUE; suffix%31", `provider=(VALUE)`, `VALUE`, []string{"specific"}},
				{"base64", base64.StdEncoding.EncodeToString([]byte("provider=VALUE padding for decoding")), `provider=(VALUE)`, `VALUE`, []string{"specific"}},
				{"percent prefix inside base64", base64.StdEncoding.EncodeToString([]byte("%70rovider=VALUE padding for decoding")), `provider=(VALUE)`, `VALUE`, []string{"specific"}},
			} {
				t.Run(tc.name, func(t *testing.T) {
					scanner := mustNew(t, &config.Config{Rules: []config.Rule{
						{ID: "specific", Regex: tc.specific, Specificity: 100},
						{ID: "generic", Regex: tc.generic},
					}}, WithRegexEngine(engine), WithMaxDecodeDepth(2))
					var ids []string
					for _, finding := range scanner.ScanString(tc.raw) {
						ids = append(ids, finding.RuleID)
					}
					require.Equal(t, tc.want, ids)
				})
			}
		})
	}
}

func TestSpecificitySourceRangeLimitations(t *testing.T) {
	// Full-match locations do not distinguish equal values inside one broad
	// match or encoded blob. Keep this tradeoff explicit when changing deduplication.
	for _, tc := range []struct{ raw, specific string }{
		{"provider=VALUE other=VALUE", `provider=(VALUE) other=VALUE`},
		{base64.StdEncoding.EncodeToString([]byte("provider=VALUE other=VALUE")), `provider=(VALUE)`},
	} {
		scanner := mustNew(t, &config.Config{Rules: []config.Rule{
			{ID: "specific", Regex: tc.specific, Specificity: 100},
			{ID: "generic", Regex: `other=(VALUE)`},
		}}, WithMaxDecodeDepth(1))
		findings := scanner.ScanString(tc.raw)
		require.Len(t, findings, 1)
		require.Equal(t, "specific", findings[0].RuleID)
	}
}

func TestSpecificityUsesComponentSourceRanges(t *testing.T) {
	for _, engine := range []regexp.Engine{regexp.Stdlib{}, re2.RE2{}} {
		t.Run(engine.Version(), func(t *testing.T) {
			scanner := mustNew(t, &config.Config{Rules: []config.Rule{
				// The owner runs last so component precedence is checked during final filtering.
				{ID: "owner", Regex: `owner=(ROOT)`, Specificity: -10, Components: []config.Component{{RuleID: "part", Within: "5L"}}},
				{ID: "part", Regex: `credential:\n (prefix-VALUE-suffix)`, Specificity: 100, SkipReport: true},
				{ID: "generic", Regex: `VALUE`},
			}}, WithRegexEngine(engine))
			findings := scanner.ScanString("owner=ROOT\ncredential:\n prefix-VALUE-suffix\nother=VALUE")
			require.Len(t, findings, 2)
			require.Equal(t, "generic", findings[0].RuleID)
			require.Equal(t, 4, findings[0].Location.StartLine)
			require.Equal(t, "owner", findings[1].RuleID)
			require.Len(t, findings[1].ComponentSets, 1)
		})
	}
}

func TestLocationsOverlap(t *testing.T) {
	a := report.Location{Path: "config", StartLine: 2, EndLine: 3, StartColumn: 5, EndColumn: 10}
	for _, tc := range []struct {
		name string
		b    report.Location
		want bool
	}{
		{"same", a, true},
		{"inside", report.Location{Path: "config", StartLine: 3, EndLine: 3, StartColumn: 2, EndColumn: 8}, true},
		{"shared final byte", report.Location{Path: "config", StartLine: 3, EndLine: 3, StartColumn: 10, EndColumn: 15}, true},
		{"adjacent after", report.Location{Path: "config", StartLine: 3, EndLine: 3, StartColumn: 11, EndColumn: 15}, false},
		{"adjacent before", report.Location{Path: "config", StartLine: 2, EndLine: 2, StartColumn: 1, EndColumn: 4}, false},
		{"earlier line", report.Location{Path: "config", StartLine: 1, EndLine: 1, StartColumn: 1, EndColumn: 100}, false},
		{"different path", report.Location{Path: "other", StartLine: 2, EndLine: 3, StartColumn: 5, EndColumn: 10}, false},
		{"path only", report.Location{Path: "config"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, locationsOverlap(a, tc.b))
			require.Equal(t, tc.want, locationsOverlap(tc.b, a))
		})
	}
}

func TestSpecificityRetainsEqualOrFilteredRules(t *testing.T) {
	for _, tc := range []struct {
		name, filter string
		specificity  int
		want         []string
	}{
		{"equal specificity", "", 0, []string{"specific", "generic"}},
		{"filtered provider", "true", 100, []string{"generic"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scanner := mustNew(t, &config.Config{Rules: []config.Rule{
				{ID: "specific", Regex: `VALUE`, Specificity: tc.specificity, FilterExpr: tc.filter},
				{ID: "generic", Regex: `key=(VALUE)`},
			}})
			var ids []string
			for _, finding := range scanner.ScanString("key=VALUE") {
				ids = append(ids, finding.RuleID)
			}
			require.Equal(t, tc.want, ids)
		})
	}
}

func TestSpecificityLongSourceRanges(t *testing.T) {
	const broad = `(?s)provider:\n.*(VALUE)`
	for _, patterns := range [][2]string{{broad, `VALUE`}, {`VALUE`, broad}} {
		scanner := mustNew(t, &config.Config{Rules: []config.Rule{
			{ID: "specific", Regex: patterns[0], Specificity: 100},
			{ID: "generic", Regex: patterns[1]},
		}})
		findings := scanner.ScanString("provider:\n" + strings.Repeat("padding\n", maxIndexedFindingLines) + "VALUE")
		require.Len(t, findings, 1)
		require.Equal(t, "specific", findings[0].RuleID)
	}
}
