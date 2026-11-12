package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "launchdarkly-access-token",
	Confidence:  "high",
	Description: "Uncovered a Launchdarkly Access Token, potentially compromising feature flag management and application functionality.",
	Regex:       rulebuilder.Assignment([]string{"launchdarkly"}, `(?i)`+rulebuilder.AlphaNumericExtended("40")),
	Keywords: []string{
		"launchdarkly",
	},
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `launchdarklyToken = "ki=bm50nvcz3-wjwuth1tchax6992fd-41l48soc"`, "ki=bm50nvcz3-wjwuth1tchax6992fd-41l48soc"),
	},
})
