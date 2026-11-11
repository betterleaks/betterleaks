package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	Description: "Found a Looker Client ID, risking unauthorized access to a Looker account and exposing sensitive data.",
	ID:          "looker-client-id",
	Confidence:  "medium",
	Regex:       Assignment([]string{"looker"}, `(?i)`+AlphaNumeric("20")),
	Keywords:    []string{"looker"},
	FilterExpr:  `entropy(finding["secret"]) < 3.0 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("looker assignment", `lookerToken = "5fbbd6p84oe7ut4qrtte"`, "5fbbd6p84oe7ut4qrtte"),
	},
})

var _ = Add(config.Rule{
	Description: "Found a Looker Client Secret, risking unauthorized access to a Looker account and exposing sensitive data.",
	ID:          "looker-client-secret",
	Confidence:  "medium",
	Regex:       Assignment([]string{"looker"}, `(?i)`+AlphaNumeric("24")),
	Keywords:    []string{"looker"},
	FilterExpr:  `entropy(finding["secret"]) < 3.0 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("looker assignment", `lookerToken = "5fbbd6p84oe7ut4qrttebiwa"`, "5fbbd6p84oe7ut4qrttebiwa"),
	},
})
