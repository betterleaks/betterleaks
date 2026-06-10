package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func GoCardless() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "gocardless-api-token",
		Description: "Detected a GoCardless API token, potentially risking unauthorized direct debit payment operations and financial data exposure.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"gocardless"}, `live_(?i)[a-z0-9\-_=]{40}`, true),

		Keywords: []string{
			"live_",
			"gocardless",
		},
		ValidateCEL: `cel.bind(r,
  http.get("https://api.gocardless.com/customers?limit=1", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json",
    "GoCardless-Version": "2015-07-06"
  }),
  r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)
)`,
		Filter: utils.MinEntropy(3.5),
	}

	// validate
	tps := utils.GenerateSampleSecrets("gocardless", "live_"+secrets.NewSecret(utils.AlphaNumericExtended("40")))
	return utils.Validate(r, tps, nil)
}
