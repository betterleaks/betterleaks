package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "squarespace-access-token",
	Confidence:  "medium",
	Description: "Identified a Squarespace Access Token, which may compromise website management and content control on Squarespace.",
	Regex:       Assignment([]string{"squarespace"}, `(?i)`+Hex8_4_4_4_12()),

	Keywords: []string{
		"squarespace",
	},
	Tests: []config.RuleTest{
		Match("squarespace assignment", `squarespaceToken = "1f7b169c-846f-218a-b552-fa82fbf86758"`, "1f7b169c-846f-218a-b552-fa82fbf86758"),
	},
})
