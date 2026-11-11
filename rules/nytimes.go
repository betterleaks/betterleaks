package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "nytimes-access-token",
	Confidence:  "high",
	Description: "Detected a Nytimes Access Token, risking unauthorized access to New York Times APIs and content services.",
	Regex: Assignment([]string{
		"nytimes", "new-york-times", "newyorktimes"},
		`(?i)`+AlphaNumericExtended("32")),

	Keywords: []string{
		"nytimes",
		"new-york-times",
		"newyorktimes",
	},
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("nytimes assignment", `nytimesToken = "5fbbd6p84oe7ut4qrttebiwar77s63do"`, "5fbbd6p84oe7ut4qrttebiwar77s63do"),
	},
})
