package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

// WooCommerce stores are self-hosted on customer-controlled domains. Avoid
// turning an arbitrary nearby store URL into a validation request target.
var _ = rulebuilder.Add(config.Rule{
	ID:          "woocommerce-consumer-secret.1",
	Confidence:  "high",
	Description: "WooCommerce REST API consumer secret, which may allow read or write access to a store with the associated consumer key.",
	Regex:       rulebuilder.Assignment([]string{"woo"}, `(?i)cs_[a-f0-9]{40}`),
	Keywords:    []string{"wooc", "woo-", "woo_", "cs_"},
	FilterExpr:  rulebuilder.MinEntropy(3.5),
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `wooToken = "cs_1f7b169c846f218ab552fa82fbf86758bf5c97d2"`, "cs_1f7b169c846f218ab552fa82fbf86758bf5c97d2"),
		rulebuilder.Match("true positive 1", `WOO_CONSUMER_SECRET="cs_1f7b169c846f218ab552fa82fbf86758bf5c97d2"`, "cs_1f7b169c846f218ab552fa82fbf86758bf5c97d2"),
		rulebuilder.Match("true positive 2", "woo-consumer-secret: cs_1f7b169c846f218ab552fa82fbf86758bf5c97d2", "cs_1f7b169c846f218ab552fa82fbf86758bf5c97d2"),
		rulebuilder.NoMatch("false positive 1", "CONSUMER_SECRET=cs_1f7b169c846f218ab552fa82fbf86758bf5c97d2"),
		rulebuilder.NoMatch("false positive 2", "WOOCOMMERCE_CONSUMER_KEY=ck_a1b2c3d4e5f60708a9b0c1d2e3f4a5b6c7d8e9f0"),
		rulebuilder.NoMatch("false positive 3", "WOOCOMMERCE_CONSUMER_SECRET=cs_short"),
		rulebuilder.NoMatch("false positive 4", "WOOCOMMERCE_CONSUMER_SECRET=cs_0000000000000000000000000000000000000000"),
	},
})
