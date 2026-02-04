package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func NPM() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "npm-access-token",
		Description: "Uncovered an npm access token, potentially compromising package management and code repository access.",
		Regex:       utils2.GenerateUniqueTokenRegex(`npm_[a-z0-9]{36}`, true),
		Entropy:     2,
		Keywords: []string{
			"npm_",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("npmAccessToken", "npm_"+secrets.NewSecret(utils2.AlphaNumeric("36")))
	return utils2.Validate(r, tps, nil)
}
