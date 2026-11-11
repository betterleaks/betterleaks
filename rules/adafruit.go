package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	Description: "Identified a potential Adafruit API Key, which could lead to unauthorized access to Adafruit services and sensitive data exposure.",
	ID:          "adafruit-api-key",
	Confidence:  "high",
	Regex:       Assignment([]string{"adafruit"}, `(?i)`+AlphaNumericExtendedShort("32")),
	Keywords:    []string{"adafruit"},
	FilterExpr:  `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("adafruit assignment", `adafruitToken = "4v8l67z---wfu0y1vd_3l1cmfzxoud8e"`, "4v8l67z---wfu0y1vd_3l1cmfzxoud8e"),
	},
})
