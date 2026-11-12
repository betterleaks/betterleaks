package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	Description: "Found a Looker Client ID, risking unauthorized access to a Looker account and exposing sensitive data.",
	ID:          "looker-client-id",
	Confidence:  "medium",
	Regex:       rulebuilder.Assignment([]string{"looker"}, `(?i)`+rulebuilder.AlphaNumeric("20")),
	Keywords:    []string{"looker"},
	FilterExpr:  `entropy(finding["secret"]) < 3.0 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `lookerToken = "5fbbd6p84oe7ut4qrtte"`, "5fbbd6p84oe7ut4qrtte"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	Description: "Found a Looker Client Secret, risking unauthorized access to a Looker account and exposing sensitive data.",
	ID:          "looker-client-secret",
	Confidence:  "medium",
	Regex:       rulebuilder.Assignment([]string{"looker"}, `(?i)`+rulebuilder.AlphaNumeric("24")),
	Keywords:    []string{"looker"},
	FilterExpr:  `entropy(finding["secret"]) < 3.0 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `lookerToken = "5fbbd6p84oe7ut4qrttebiwa"`, "5fbbd6p84oe7ut4qrttebiwa"),
	},
})
