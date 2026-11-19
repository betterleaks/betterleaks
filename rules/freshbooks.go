package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "freshbooks-access-token",
	Confidence:  "high",
	Description: "Discovered a Freshbooks Access Token, posing a risk to accounting software access and sensitive financial data exposure.",
	Regex:       rulebuilder.Assignment([]string{"freshbooks"}, `(?i)[a-z0-9]{64}`),
	Keywords: []string{
		"freshbooks",
	},
	ValidateExpr: rulebuilder.BearerGetValidationExpr("https://api.freshbooks.com/auth/api/v1/users/me", "true"),
	FilterExpr:   `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `freshbooksToken = "5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7nz6lc"`, "5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7nz6lc"),
	},
})
