package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	Description: "Identified an Intercom API Token, which could compromise customer communication channels and data privacy.",
	ID:          "intercom-api-key",
	Confidence:  "medium",
	Regex:       Assignment([]string{"intercom"}, `(?i)`+AlphaNumericExtended("60")),

	Keywords:   []string{"intercom"},
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("intercom assignment", `intercomToken = "ki=bm50nvcz3-wjwuth1tchax6992fd-41l48soc903fsrsj9cld-8001fa7"`, "ki=bm50nvcz3-wjwuth1tchax6992fd-41l48soc903fsrsj9cld-8001fa7"),
	},
})
