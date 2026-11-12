package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	Description: "Discovered a potential Asana Client ID, risking unauthorized access to Asana projects and sensitive task information.",
	ID:          "asana-client-id",
	Confidence:  "high",
	Regex:       rulebuilder.Assignment([]string{"asana"}, `(?i)`+rulebuilder.Numeric("16")),
	Keywords:    []string{"asana"},
	FilterExpr:  `entropy(finding["secret"]) < 2.75`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `asanaToken = "1779185060412984"`, "1779185060412984"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	Description: "Identified an Asana Client Secret, which could lead to compromised project management integrity and unauthorized access.",
	ID:          "asana-client-secret",
	Confidence:  "high",
	Regex:       rulebuilder.Assignment([]string{"asana"}, `(?i)`+rulebuilder.AlphaNumeric("32")),
	Keywords:    []string{"asana"},
	FilterExpr:  `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `asanaToken = "5fbbd6p84oe7ut4qrttebiwar77s63do"`, "5fbbd6p84oe7ut4qrttebiwar77s63do"),
	},
})
