package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
)

func CheckoutSecretKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "checkout-secret-key",
		Description: "Checkout.com secret key.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"checkout"}, `sk_[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`, true),
		Keywords:    []string{"checkout"},
		ValidateExpr: `let r = http.get("https://api.checkout.com/workflows", {
    "Authorization": "Bearer " + finding["secret"]
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	}

	// validate
	tps := []string{
		`CHECKOUT_SECRET_KEY=sk_0b9b5db6-fabc-49d0-b68f-13343bb4f708`,
	}
	fps := []string{
		`CHECKOUT_SECRET_KEY=sk_0b9b5db6-fabc-49d0-b68f-13343bb4f70`,
	}
	return utils.Validate(r, tps, fps)
}
