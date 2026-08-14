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
		Filter: `filter.entropy(finding["secret"]) < 3.5 || filter.tokenRatio(finding["secret"]) >= 2.5`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("coinbase", secrets.NewSecretWithEntropy(utils.AlphaNumericExtendedShort("64"), 3.5))
	return utils.Validate(r, tps, nil)
}
