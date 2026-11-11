package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "stripe-access-token",
	Confidence:  "high",
	Description: "Found a Stripe Access Token, posing a risk to payment processing services and sensitive financial data.",
	Regex:       Token(`(?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99}`),
	Keywords: []string{
		"sk_test",
		"sk_live",
		"sk_prod",
		"rk_test",
		"rk_live",
		"rk_prod",
	},
	ValidateExpr: `let r = http.get("https://api.stripe.com/v1/account", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 && (r.json?.object ?? "") == "account" ? {
    "result": "valid"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: `matchesAny(finding["secret"], ["^sk_live_a2V5Xz"])
|| entropy(finding["secret"]) <= 2.0`,
	Tests: []config.RuleTest{
		Match("stripe assignment", `stripeToken = "sk_test_5fbbd6p84oe7ut4qrttebiwar77s63"`, "sk_test_5fbbd6p84oe7ut4qrttebiwar77s63"),
		Match("stripe assignment 2", `stripeToken = "sk_prod_5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7nz6lca8hqn2j0qefi1vg8f9p1t7tnza246j0vcrp"`, "sk_prod_5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7nz6lca8hqn2j0qefi1vg8f9p1t7tnza246j0vcrp"),
		Match("bare secret", "sk_test_51OuEMLAlTWGaDypq4P5cuDHbuKeG4tAGPYHJpEXQ7zE8mKK3jkhTFPvCxnSSK5zB5EQZrJsYdsatNmAHGgb0vSKD00GTMSWRHs", "sk_test_51OuEMLAlTWGaDypq4P5cuDHbuKeG4tAGPYHJpEXQ7zE8mKK3jkhTFPvCxnSSK5zB5EQZrJsYdsatNmAHGgb0vSKD00GTMSWRHs"),
		Match("bare secret 2", "rk_prod_51OuEMLAlTWGaDypquDn9aZigaJOsa9NR1w1BxZXs9JlYsVVkv5XDu6aLmAxwt5Tgun5WcSwQMKzQyqV16c9iD4sx00BRijuoon", "rk_prod_51OuEMLAlTWGaDypquDn9aZigaJOsa9NR1w1BxZXs9JlYsVVkv5XDu6aLmAxwt5Tgun5WcSwQMKzQyqV16c9iD4sx00BRijuoon"),
		NoMatch("false positive 1", `nonMatchingToken := "task_test_5fbbd6p84oe7ut4qrttebiwar77s63"`),
		NoMatch("false positive 2", `HIGHNOTE_API_KEY="sk_live_a2V5XzAxS1BSWE1LTjBEWE1INlpBU0VEWjU2VFE3LFdjOWxFMTNDS29xRkdlYU9uMUpDbUpTZWE"`),
	},
})
