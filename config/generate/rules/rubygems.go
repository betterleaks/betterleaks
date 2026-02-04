package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func RubyGemsAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "rubygems-api-token",
		Description: "Identified a Rubygem API token, potentially compromising Ruby library distribution and package management.",
		Regex:       utils2.GenerateUniqueTokenRegex(`rubygems_[a-f0-9]{48}`, false),
		Entropy:     2,
		Keywords: []string{
			"rubygems_",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("rubygemsAPIToken", "rubygems_"+secrets.NewSecret(utils2.Hex("48")))
	return utils2.Validate(r, tps, nil)
}
