package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func RubyGemsAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "rubygems-api-token",
		Description: "Identified a Rubygem API token, potentially compromising Ruby library distribution and package management.",
		Regex:       utils.GenerateUniqueTokenRegex(`rubygems_[a-f0-9]{48}`, false),
		Entropy:     2,
		Keywords: []string{
			"rubygems_",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("rubygemsAPIToken", "rubygems_"+secrets.NewSecretWithEntropy(utils.Hex("48"), 2))
	return utils.Validate(r, tps, nil)
}
