package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "gitter-access-token",
	Confidence:  "high",
	Description: "Uncovered a Gitter Access Token, which may lead to unauthorized access to chat and communication services.",
	Regex: Assignment([]string{"gitter"},
		`(?i)`+AlphaNumericExtendedShort("40")),

	Keywords: []string{
		"gitter",
	},
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("gitter assignment", `gitterToken = "4v8l67z---wfu0y1vd_3l1cmfzxoud8et6xy88z3"`, "4v8l67z---wfu0y1vd_3l1cmfzxoud8et6xy88z3"),
	},
})
