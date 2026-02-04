package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func AlgoliaApiKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Identified an Algolia API Key, which could result in unauthorized search operations and data exposure on Algolia-managed platforms.",
		RuleID:      "algolia-api-key",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"algolia"}, `[a-z0-9]{32}`, true),
		Keywords:    []string{"algolia"},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("algolia", secrets.NewSecret(utils2.Hex("32")))
	return utils2.Validate(r, tps, nil)
}
