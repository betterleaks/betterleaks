package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "rapidapi-access-token",
	Confidence:  "high",
	Description: "Uncovered a RapidAPI Access Token, which could lead to unauthorized access to various APIs and data services.",
	Regex:       rulebuilder.Assignment([]string{"rapidapi"}, `(?i)`+rulebuilder.AlphaNumericExtendedShort("50")),
	Keywords: []string{
		"rapidapi",
	},
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `rapidapiToken = "4v8l67z---wfu0y1vd_3l1cmfzxoud8et6xy88z3pomb2z7epj"`, "4v8l67z---wfu0y1vd_3l1cmfzxoud8et6xy88z3pomb2z7epj"),
	},
})
