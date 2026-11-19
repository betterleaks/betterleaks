package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "checkout-secret-key",
	Confidence:  "medium",
	Description: "Checkout.com secret key.",
	Regex:       rulebuilder.Assignment([]string{"checkout"}, `(?i)sk_[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`),
	Keywords:    []string{"checkout"},
	ValidateExpr: `let r = http.get("https://api.checkout.com/workflows", {
    "Authorization": "Bearer " + finding["secret"]
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "CHECKOUT_SECRET_KEY=sk_0b9b5db6-fabc-49d0-b68f-13343bb4f708", "sk_0b9b5db6-fabc-49d0-b68f-13343bb4f708"),
		rulebuilder.NoMatch("false positive 1", "CHECKOUT_SECRET_KEY=sk_0b9b5db6-fabc-49d0-b68f-13343bb4f70"),
	},
})
