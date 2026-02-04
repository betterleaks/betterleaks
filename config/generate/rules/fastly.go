package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func FastlyAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Uncovered a Fastly API key, which may compromise CDN and edge cloud services, leading to content delivery and security issues.",
		RuleID:      "fastly-api-token",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"fastly"}, utils2.AlphaNumericExtended("32"), true),

		Keywords: []string{"fastly"},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("fastly", secrets.NewSecret(utils2.AlphaNumericExtended("32")))
	return utils2.Validate(r, tps, nil)
}
