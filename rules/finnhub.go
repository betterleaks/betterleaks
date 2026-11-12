package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "finnhub-access-token",
	Confidence:  "high",
	Description: "Found a Finnhub Access Token, risking unauthorized access to financial market data and analytics.",
	Regex:       rulebuilder.Assignment([]string{"finnhub"}, `(?i)`+rulebuilder.AlphaNumeric("20")),
	Keywords: []string{
		"finnhub",
	},
	FilterExpr: `entropy(finding["secret"]) < 3.0 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `finnhubToken = "5fbbd6p84oe7ut4qrtte"`, "5fbbd6p84oe7ut4qrtte"),
	},
})
