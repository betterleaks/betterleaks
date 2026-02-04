package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func TravisCIAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "travisci-access-token",
		Description: "Identified a Travis CI Access Token, potentially compromising continuous integration services and codebase security.",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"travis"}, utils2.AlphaNumeric("22"), true),

		Keywords: []string{
			"travis",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("travis", secrets.NewSecret(utils2.AlphaNumeric("22")))
	return utils2.Validate(r, tps, nil)
}
