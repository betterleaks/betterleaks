package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func KrakenAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "kraken-access-token",
		Description: "Identified a Kraken Access Token, potentially compromising cryptocurrency trading accounts and financial security.",
		Regex: utils2.GenerateSemiGenericRegex([]string{"kraken"},
			utils2.AlphaNumericExtendedLong("80,90"), true),

		Keywords: []string{
			"kraken",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("kraken", secrets.NewSecret(utils2.AlphaNumericExtendedLong("80,90")))
	return utils2.Validate(r, tps, nil)
}
