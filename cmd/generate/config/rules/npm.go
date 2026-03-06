package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func NPM() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "npm-access-token",
		Description: "Uncovered an npm access token, potentially compromising package management and code repository access.",
		Regex:       utils.GenerateUniqueTokenRegex(`npm_[a-z0-9]{36}`, true),
		Entropy:     2,
		Keywords: []string{
			"npm_",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("npmAccessToken", "npm_"+secrets.NewSecretWithEntropy(utils.AlphaNumeric("36"), 2))
	return utils.Validate(r, tps, nil)
}
