package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func CoinbaseAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "coinbase-access-token",
		Description: "Detected a Coinbase Access Token, posing a risk of unauthorized access to cryptocurrency accounts and financial transactions.",
		Regex: utils2.GenerateSemiGenericRegex([]string{"coinbase"},
			utils2.AlphaNumericExtendedShort("64"), true),
		Keywords: []string{
			"coinbase",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("coinbase", secrets.NewSecret(utils2.AlphaNumericExtendedShort("64")))
	return utils2.Validate(r, tps, nil)
}
