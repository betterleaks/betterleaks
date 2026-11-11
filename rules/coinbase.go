package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "coinbase-access-token",
	Confidence:  "medium",
	Description: "Detected a Coinbase Access Token, posing a risk of unauthorized access to cryptocurrency accounts and financial transactions.",
	Regex: Assignment([]string{"coinbase"},
		`(?i)`+AlphaNumericExtendedShort("64")),
	Keywords: []string{
		"coinbase",
	},
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("coinbase assignment", `coinbaseToken = "4v8l67z---wfu0y1vd_3l1cmfzxoud8et6xy88z3pomb2z7epjl8r_uz93d025di"`, "4v8l67z---wfu0y1vd_3l1cmfzxoud8et6xy88z3pomb2z7epjl8r_uz93d025di"),
	},
})
