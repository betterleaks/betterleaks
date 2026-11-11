package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "shippo-api-token",
	Confidence:  "high",
	Description: "Discovered a Shippo API token, potentially compromising shipping services and customer order data.",
	Regex:       Token(`shippo_(?:live|test)_[a-fA-F0-9]{40}`),
	Keywords: []string{
		"shippo_",
	},
	FilterExpr: `entropy(finding["secret"]) <= 2.0`,
	Tests: []config.RuleTest{
		Match("shippo assignment", `shippoToken = "shippo_live_1f7b169c846f218ab552fa82fbf86758bf5c97d2"`, "shippo_live_1f7b169c846f218ab552fa82fbf86758bf5c97d2"),
		Match("shippo assignment 2", `shippoToken = "shippo_test_1f7b169c846f218ab552fa82fbf86758bf5c97d2"`, "shippo_test_1f7b169c846f218ab552fa82fbf86758bf5c97d2"),
	},
})
