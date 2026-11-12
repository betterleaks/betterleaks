package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "plaid-client-id",
	Confidence:  "medium",
	Description: "Uncovered a Plaid Client ID, which could lead to unauthorized financial service integrations and data breaches.",
	Regex:       rulebuilder.Assignment([]string{"plaid"}, `(?i)`+rulebuilder.AlphaNumeric("24")),
	Keywords: []string{
		"plaid",
	},
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `plaidToken = "RFbD56TI2smTyVsGd5Xav0yu"`, "RFbD56TI2smTyVsGd5Xav0yu"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "plaid-secret-key",
	Confidence:  "medium",
	Description: "Detected a Plaid Secret key, risking unauthorized access to financial accounts and sensitive transaction data.",
	Regex:       rulebuilder.Assignment([]string{"plaid"}, `(?i)`+rulebuilder.AlphaNumeric("30")),
	Keywords: []string{
		"plaid",
	},
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `plaidToken = "5fbbd6p84oe7ut4qrttebiwar77s63"`, "5fbbd6p84oe7ut4qrttebiwar77s63"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "plaid-api-token",
	Confidence:  "high",
	Description: "Discovered a Plaid API Token, potentially compromising financial data aggregation and banking services.",
	Regex: rulebuilder.Assignment(
		[]string{"plaid"},
		"(?i)access-(?:sandbox|development|production)-"+rulebuilder.Hex8_4_4_4_12(),
	),
	Keywords: []string{
		"plaid",
	},
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `plaidToken = "access-production-f7b169c8-46f2-18ab-552f-a82fbf86758b"`, "access-production-f7b169c8-46f2-18ab-552f-a82fbf86758b"),
	},
})
