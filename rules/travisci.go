package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "travisci-access-token",
	Confidence:  "medium",
	Description: "Identified a Travis CI Access Token, potentially compromising continuous integration services and codebase security.",
	Regex:       rulebuilder.Assignment([]string{"travis"}, `(?i)`+rulebuilder.AlphaNumeric("22")),
	Keywords: []string{
		"travis",
	},
	FilterExpr: `entropy(finding["secret"]) < 3.0 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `travisToken = "5fbbd6p84oe7ut4qrttebi"`, "5fbbd6p84oe7ut4qrttebi"),
	},
})
