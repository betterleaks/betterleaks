package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func RedirectPizzaAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "redirect-pizza-api-token.1",
		Description: "redirect.pizza API token.",
		Regex:       utils.GenerateUniqueTokenRegex(`rpa_[A-Za-z0-9]{30}`, false),
		Keywords:    []string{"rpa_"},
		ValidateExpr: `let r = http.get("https://redirect.pizza/api/v1/domains", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status == 401 && (r.json?.message ?? "") == "Unauthenticated." ? {
    "result": "invalid",
    "reason": "Unauthenticated"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.5),
	}

	// validate
	tps := []string{
		"REDIRECT_PIZZA_TOKEN=rpa_" + secrets.NewSecretWithEntropy(utils.AlphaNumeric("30"), 3.5),
	}
	fps := []string{
		`REDIRECT_PIZZA_TOKEN=rpa_short`,
		`REDIRECT_PIZZA_TOKEN=rpa_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`,
		`RUNPOD_API_KEY=rpa_ABC123DEF456GHI789JKL012MNO345PQR678STUVX9y2z7`,
	}
	return utils.Validate(r, tps, fps)
}
