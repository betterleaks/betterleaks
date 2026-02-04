package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func PlaidAccessID() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "plaid-client-id",
		Description: "Uncovered a Plaid Client ID, which could lead to unauthorized financial service integrations and data breaches.",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"plaid"}, utils2.AlphaNumeric("24"), true),

		Entropy: 3.5,
		Keywords: []string{
			"plaid",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("plaid", secrets.NewSecret(`[a-zA-Z0-9]{24}`))
	return utils2.Validate(r, tps, nil)
}

func PlaidSecretKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "plaid-secret-key",
		Description: "Detected a Plaid Secret key, risking unauthorized access to financial accounts and sensitive transaction data.",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"plaid"}, utils2.AlphaNumeric("30"), true),

		Entropy: 3.5,
		Keywords: []string{
			"plaid",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("plaid", secrets.NewSecret(utils2.AlphaNumeric("30")))
	return utils2.Validate(r, tps, nil)
}

func PlaidAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "plaid-api-token",
		Description: "Discovered a Plaid API Token, potentially compromising financial data aggregation and banking services.",
		Regex: utils2.GenerateSemiGenericRegex([]string{"plaid"},
			"access-(?:sandbox|development|production)-"+utils2.Hex8_4_4_4_12(), true),

		Keywords: []string{
			"plaid",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("plaid", secrets.NewSecret("access-(?:sandbox|development|production)-"+utils2.Hex8_4_4_4_12()))
	return utils2.Validate(r, tps, nil)
}
