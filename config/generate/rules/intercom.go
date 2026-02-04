package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func Intercom() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Identified an Intercom API Token, which could compromise customer communication channels and data privacy.",
		RuleID:      "intercom-api-key",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"intercom"}, utils2.AlphaNumericExtended("60"), true),

		Keywords: []string{"intercom"},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("intercom", secrets.NewSecret(utils2.AlphaNumericExtended("60")))
	return utils2.Validate(r, tps, nil)
}
