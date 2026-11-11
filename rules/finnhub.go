package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "finnhub-access-token",
	Confidence:  "high",
	Description: "Found a Finnhub Access Token, risking unauthorized access to financial market data and analytics.",
	Regex:       Assignment([]string{"finnhub"}, `(?i)`+AlphaNumeric("20")),

	Keywords: []string{
		"finnhub",
	},
	FilterExpr: `entropy(finding["secret"]) < 3.0 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("finnhub assignment", `finnhubToken = "5fbbd6p84oe7ut4qrtte"`, "5fbbd6p84oe7ut4qrtte"),
	},
})
