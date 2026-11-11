package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "launchdarkly-access-token",
	Confidence:  "high",
	Description: "Uncovered a Launchdarkly Access Token, potentially compromising feature flag management and application functionality.",
	Regex:       Assignment([]string{"launchdarkly"}, `(?i)`+AlphaNumericExtended("40")),

	Keywords: []string{
		"launchdarkly",
	},
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("launchdarkly assignment", `launchdarklyToken = "ki=bm50nvcz3-wjwuth1tchax6992fd-41l48soc"`, "ki=bm50nvcz3-wjwuth1tchax6992fd-41l48soc"),
	},
})
