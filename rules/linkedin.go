package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "linkedin-client-id",
	Confidence:  "medium",
	Description: "Found a LinkedIn Client ID, risking unauthorized access to LinkedIn integrations and professional data exposure.",
	Regex:       rulebuilder.Assignment([]string{"linked[_-]?in"}, `(?i)`+rulebuilder.AlphaNumeric("14")),
	Keywords: []string{
		"linkedin",
		"linked_in",
		"linked-in",
	},
	FilterExpr: rulebuilder.MinEntropyAndTokenEfficiency,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `linkedinToken = "5fbbd6p84oe7ut"`, "5fbbd6p84oe7ut"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "linkedin-client-secret",
	Confidence:  "medium",
	Description: "Discovered a LinkedIn Client secret, potentially compromising LinkedIn application integrations and user data.",
	Regex:       rulebuilder.Assignment([]string{"linked[_-]?in"}, `(?i)`+rulebuilder.AlphaNumeric("16")),
	Keywords: []string{
		"linkedin",
		"linked_in",
		"linked-in",
	},
	FilterExpr: rulebuilder.MinEntropyAndTokenEfficiency,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `linkedinToken = "5fbbd6p84oe7ut4q"`, "5fbbd6p84oe7ut4q"),
	},
})
