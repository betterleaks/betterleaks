package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "nytimes-access-token",
	Confidence:  "high",
	Description: "Detected a Nytimes Access Token, risking unauthorized access to New York Times APIs and content services.",
	Regex: rulebuilder.Assignment(
		[]string{
			"nytimes", "new-york-times", "newyorktimes"},
		`(?i)[a-z0-9=_\-]{32}`,
	),
	Keywords: []string{
		"nytimes",
		"new-york-times",
		"newyorktimes",
	},
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `nytimesToken = "5fbbd6p84oe7ut4qrttebiwar77s63do"`, "5fbbd6p84oe7ut4qrttebiwar77s63do"),
	},
})
