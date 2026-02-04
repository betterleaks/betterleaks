package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func GoCardless() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "gocardless-api-token",
		Description: "Detected a GoCardless API token, potentially risking unauthorized direct debit payment operations and financial data exposure.",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"gocardless"}, `live_(?i)[a-z0-9\-_=]{40}`, true),

		Keywords: []string{
			"live_",
			"gocardless",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("gocardless", "live_"+secrets.NewSecret(utils2.AlphaNumericExtended("40")))
	return utils2.Validate(r, tps, nil)
}
