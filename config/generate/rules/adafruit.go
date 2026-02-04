package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func AdafruitAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Identified a potential Adafruit API Key, which could lead to unauthorized access to Adafruit services and sensitive data exposure.",
		RuleID:      "adafruit-api-key",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"adafruit"}, utils2.AlphaNumericExtendedShort("32"), true),
		Keywords:    []string{"adafruit"},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("adafruit", secrets.NewSecret(utils2.AlphaNumericExtendedShort("32")))
	return utils2.Validate(r, tps, nil)
}
