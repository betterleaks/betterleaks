package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	Description: "Identified a Finicity Client Secret, which could lead to compromised financial service integrations and data breaches.",
	ID:          "finicity-client-secret",
	Confidence:  "high",
	Regex:       rulebuilder.Assignment([]string{"finicity"}, `(?i)[a-z0-9]{20}`),
	Keywords:    []string{"finicity"},
	FilterExpr:  `entropy(finding["secret"]) < 3.0 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `finicityToken = "5fbbd6p84oe7ut4qrtte"`, "5fbbd6p84oe7ut4qrtte"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	Description: "Detected a Finicity API token, potentially risking financial data access and unauthorized financial operations.",
	ID:          "finicity-api-token",
	Confidence:  "high",
	Regex:       rulebuilder.Assignment([]string{"finicity"}, `(?i)[a-f0-9]{32}`),
	Keywords:    []string{"finicity"},
	FilterExpr:  `entropy(finding["secret"]) < 3.3 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `finicityToken = "1f7b169c846f218ab552fa82fbf86758"`, "1f7b169c846f218ab552fa82fbf86758"),
	},
})
