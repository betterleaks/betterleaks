package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func BittrexAccessKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Identified a Bittrex Access Key, which could lead to unauthorized access to cryptocurrency trading accounts and financial loss.",
		RuleID:      "bittrex-access-key",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"bittrex"}, utils2.AlphaNumeric("32"), true),
		Keywords:    []string{"bittrex"},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("bittrex", secrets.NewSecret(utils2.AlphaNumeric("32")))
	return utils2.Validate(r, tps, nil)
}

func BittrexSecretKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Detected a Bittrex Secret Key, potentially compromising cryptocurrency transactions and financial security.",
		RuleID:      "bittrex-secret-key",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"bittrex"}, utils2.AlphaNumeric("32"), true),

		Keywords: []string{"bittrex"},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("bittrex", secrets.NewSecret(utils2.AlphaNumeric("32")))
	return utils2.Validate(r, tps, nil)
}
