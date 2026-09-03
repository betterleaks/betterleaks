package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

func KucoinAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "kucoin-access-token",
		Confidence:  "high",
		Description: "Found a Kucoin Access Token, risking unauthorized access to cryptocurrency exchange services and transactions.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"kucoin"}, utils.Hex("24"), true),

		Keywords: []string{
			"kucoin",
		},
		Filter: `filter.entropy(finding["secret"]) < 3.0 || filter.tokenRatio(finding["secret"]) >= 2.5`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("kucoin", secrets.NewSecretWithEntropy(utils.Hex("24"), 3.0))
	return utils.Validate(r, tps, nil)
}

func KucoinSecretKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "kucoin-secret-key",
		Confidence:  "high",
		Description: "Discovered a Kucoin Secret Key, which could lead to compromised cryptocurrency operations and financial data breaches.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"kucoin"}, utils.Hex8_4_4_4_12(), true),

		Keywords: []string{
			"kucoin",
		},
		Filter: `filter.entropy(finding["secret"]) < 3.3 || filter.tokenRatio(finding["secret"]) >= 2.5`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("kucoin", secrets.NewSecretWithEntropy(utils.Hex8_4_4_4_12(), 3.3))
	return utils.Validate(r, tps, nil)
}
