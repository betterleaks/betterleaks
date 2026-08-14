package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func KrakenAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "kraken-access-token",
		Confidence:  "high",
		Description: "Identified a Kraken Access Token, potentially compromising cryptocurrency trading accounts and financial security.",
		Regex: utils.GenerateSemiGenericRegex([]string{"kraken"},
			utils.AlphaNumericExtendedLong("80,90"), true),

		Keywords: []string{
			"kraken",
		},
		Filter: `filter.entropy(finding["secret"]) < 4.0 || filter.tokenRatio(finding["secret"]) >= 2.5`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("kraken", secrets.NewSecretWithEntropy(utils.AlphaNumericExtendedLong("80,90"), 4.0))
	return utils.Validate(r, tps, nil)
}
