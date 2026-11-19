package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "coinbase-access-token",
	Confidence:  "medium",
	Description: "Detected a Coinbase Access Token, posing a risk of unauthorized access to cryptocurrency accounts and financial transactions.",
	Regex:       rulebuilder.Assignment([]string{"coinbase"}, `(?i)[a-z0-9_-]{64}`),
	Keywords: []string{
		"coinbase",
	},
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `coinbaseToken = "4v8l67z---wfu0y1vd_3l1cmfzxoud8et6xy88z3pomb2z7epjl8r_uz93d025di"`, "4v8l67z---wfu0y1vd_3l1cmfzxoud8et6xy88z3pomb2z7epjl8r_uz93d025di"),
	},
})
