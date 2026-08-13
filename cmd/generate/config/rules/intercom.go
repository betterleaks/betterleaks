package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func Intercom() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Identified an Intercom API Token, which could compromise customer communication channels and data privacy.",
		RuleID:      "intercom-api-key",
		Confidence:  "medium",
		Regex:       utils.GenerateSemiGenericRegex([]string{"intercom"}, utils.AlphaNumericExtended("60"), true),

		Keywords: []string{"intercom"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("intercom", secrets.NewSecret(utils.AlphaNumericExtended("60")))
	return utils.Validate(r, tps, nil)
}
