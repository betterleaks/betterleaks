package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "kucoin-access-token",
	Confidence:  "high",
	Description: "Found a Kucoin Access Token, risking unauthorized access to cryptocurrency exchange services and transactions.",
	Regex:       rulebuilder.Assignment([]string{"kucoin"}, `(?i)[a-f0-9]{24}`),
	Keywords: []string{
		"kucoin",
	},
	FilterExpr: `entropy(finding["secret"]) < 3.0 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `kucoinToken = "1f7b169c846f218ab552fa82"`, "1f7b169c846f218ab552fa82"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "kucoin-secret-key",
	Confidence:  "high",
	Description: "Discovered a Kucoin Secret Key, which could lead to compromised cryptocurrency operations and financial data breaches.",
	Regex:       rulebuilder.Assignment([]string{"kucoin"}, `(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
	Keywords: []string{
		"kucoin",
	},
	FilterExpr: `entropy(finding["secret"]) < 3.3 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `kucoinToken = "1f7b169c-846f-218a-b552-fa82fbf86758"`, "1f7b169c-846f-218a-b552-fa82fbf86758"),
	},
})
