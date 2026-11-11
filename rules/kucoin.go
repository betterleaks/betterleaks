package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "kucoin-access-token",
	Confidence:  "high",
	Description: "Found a Kucoin Access Token, risking unauthorized access to cryptocurrency exchange services and transactions.",
	Regex:       Assignment([]string{"kucoin"}, `(?i)`+Hex("24")),

	Keywords: []string{
		"kucoin",
	},
	FilterExpr: `entropy(finding["secret"]) < 3.0 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("kucoin assignment", `kucoinToken = "1f7b169c846f218ab552fa82"`, "1f7b169c846f218ab552fa82"),
	},
})

var _ = Add(config.Rule{
	ID:          "kucoin-secret-key",
	Confidence:  "high",
	Description: "Discovered a Kucoin Secret Key, which could lead to compromised cryptocurrency operations and financial data breaches.",
	Regex:       Assignment([]string{"kucoin"}, `(?i)`+Hex8_4_4_4_12()),

	Keywords: []string{
		"kucoin",
	},
	FilterExpr: `entropy(finding["secret"]) < 3.3 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("kucoin assignment", `kucoinToken = "1f7b169c-846f-218a-b552-fa82fbf86758"`, "1f7b169c-846f-218a-b552-fa82fbf86758"),
	},
})
