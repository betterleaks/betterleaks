package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func KucoinAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "kucoin-access-token",
		Description: "Found a Kucoin Access Token, risking unauthorized access to cryptocurrency exchange services and transactions.",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"kucoin"}, utils2.Hex("24"), true),

		Keywords: []string{
			"kucoin",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("kucoin", secrets.NewSecret(utils2.Hex("24")))
	return utils2.Validate(r, tps, nil)
}

func KucoinSecretKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "kucoin-secret-key",
		Description: "Discovered a Kucoin Secret Key, which could lead to compromised cryptocurrency operations and financial data breaches.",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"kucoin"}, utils2.Hex8_4_4_4_12(), true),

		Keywords: []string{
			"kucoin",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("kucoin", secrets.NewSecret(utils2.Hex8_4_4_4_12()))
	return utils2.Validate(r, tps, nil)
}
