package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "squarespace-access-token",
	Confidence:  "medium",
	Description: "Identified a Squarespace Access Token, which may compromise website management and content control on Squarespace.",
	Regex:       rulebuilder.Assignment([]string{"squarespace"}, `(?i)`+rulebuilder.Hex8_4_4_4_12()),
	Keywords: []string{
		"squarespace",
	},
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `squarespaceToken = "1f7b169c-846f-218a-b552-fa82fbf86758"`, "1f7b169c-846f-218a-b552-fa82fbf86758"),
	},
})
