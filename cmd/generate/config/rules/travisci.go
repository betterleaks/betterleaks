package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func TravisCIAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "travisci-access-token",
		Confidence:  "high",
		Description: "Identified a Travis CI Access Token, potentially compromising continuous integration services and codebase security.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"travis"}, utils.AlphaNumeric("22"), true),

		Keywords: []string{
			"travis",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("travis", secrets.NewSecret(utils.AlphaNumeric("22")))
	return utils.Validate(r, tps, nil)
}
