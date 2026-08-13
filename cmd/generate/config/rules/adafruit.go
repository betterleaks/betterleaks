package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func AdafruitAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Identified a potential Adafruit API Key, which could lead to unauthorized access to Adafruit services and sensitive data exposure.",
		RuleID:      "adafruit-api-key",
		Confidence:  "high",
		Regex:       utils.GenerateSemiGenericRegex([]string{"adafruit"}, utils.AlphaNumericExtendedShort("32"), true),
		Keywords:    []string{"adafruit"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("adafruit", secrets.NewSecret(utils.AlphaNumericExtendedShort("32")))
	return utils.Validate(r, tps, nil)
}
