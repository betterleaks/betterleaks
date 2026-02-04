package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func DroneciAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "droneci-access-token",
		Description: "Detected a Droneci Access Token, potentially compromising continuous integration and deployment workflows.",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"droneci"}, utils2.AlphaNumeric("32"), true),

		Keywords: []string{
			"droneci",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("droneci", secrets.NewSecret(utils2.AlphaNumeric("32")))
	return utils2.Validate(r, tps, nil)
}
