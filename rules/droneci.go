package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "droneci-access-token",
	Confidence:  "high",
	Description: "Detected a Droneci Access Token, potentially compromising continuous integration and deployment workflows.",
	Regex:       rulebuilder.Assignment([]string{"droneci"}, `(?i)`+rulebuilder.AlphaNumeric("32")),
	Keywords: []string{
		"droneci",
	},
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `droneciToken = "5fbbd6p84oe7ut4qrttebiwar77s63do"`, "5fbbd6p84oe7ut4qrttebiwar77s63do"),
	},
})
