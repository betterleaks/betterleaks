package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func CoinbaseAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "coinbase-access-token",
		Confidence:  "medium",
		Description: "Detected a Coinbase Access Token, posing a risk of unauthorized access to cryptocurrency accounts and financial transactions.",
		Regex: utils.GenerateSemiGenericRegex([]string{"coinbase"},
			utils.AlphaNumericExtendedShort("64"), true),
		Keywords: []string{
			"coinbase",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("coinbase", secrets.NewSecret(utils.AlphaNumericExtendedShort("64")))
	return utils.Validate(r, tps, nil)
}
