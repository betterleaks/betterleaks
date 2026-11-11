package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	Description: "Identified a Finicity Client Secret, which could lead to compromised financial service integrations and data breaches.",
	ID:          "finicity-client-secret",
	Confidence:  "high",
	Regex:       Assignment([]string{"finicity"}, `(?i)`+AlphaNumeric("20")),

	Keywords:   []string{"finicity"},
	FilterExpr: `entropy(finding["secret"]) < 3.0 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("finicity assignment", `finicityToken = "5fbbd6p84oe7ut4qrtte"`, "5fbbd6p84oe7ut4qrtte"),
	},
})

var _ = Add(config.Rule{
	Description: "Detected a Finicity API token, potentially risking financial data access and unauthorized financial operations.",
	ID:          "finicity-api-token",
	Confidence:  "high",
	Regex:       Assignment([]string{"finicity"}, `(?i)`+Hex("32")),

	Keywords:   []string{"finicity"},
	FilterExpr: `entropy(finding["secret"]) < 3.3 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("finicity assignment", `finicityToken = "1f7b169c846f218ab552fa82fbf86758"`, "1f7b169c846f218ab552fa82fbf86758"),
	},
})
