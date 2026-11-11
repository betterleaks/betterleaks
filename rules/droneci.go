package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "droneci-access-token",
	Confidence:  "high",
	Description: "Detected a Droneci Access Token, potentially compromising continuous integration and deployment workflows.",
	Regex:       Assignment([]string{"droneci"}, `(?i)`+AlphaNumeric("32")),

	Keywords: []string{
		"droneci",
	},
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("droneci assignment", `droneciToken = "5fbbd6p84oe7ut4qrttebiwar77s63do"`, "5fbbd6p84oe7ut4qrttebiwar77s63do"),
	},
})
