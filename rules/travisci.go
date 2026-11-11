package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "travisci-access-token",
	Confidence:  "medium",
	Description: "Identified a Travis CI Access Token, potentially compromising continuous integration services and codebase security.",
	Regex:       Assignment([]string{"travis"}, `(?i)`+AlphaNumeric("22")),

	Keywords: []string{
		"travis",
	},
	FilterExpr: `entropy(finding["secret"]) < 3.0 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("travis assignment", `travisToken = "5fbbd6p84oe7ut4qrttebi"`, "5fbbd6p84oe7ut4qrttebi"),
	},
})
