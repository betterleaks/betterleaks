package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func ReadMe() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "readme-api-token",
		Description: "Detected a Readme API token, risking unauthorized documentation management and content exposure.",
		Regex:       utils2.GenerateUniqueTokenRegex(`rdme_[a-z0-9]{70}`, false),
		Entropy:     2,
		Keywords: []string{
			"rdme_",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("api-token", "rdme_"+secrets.NewSecret(utils2.AlphaNumeric("70")))

	fps := []string{
		`const API_KEY = 'rdme_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX';`,
	}
	return utils2.Validate(r, tps, fps)
}
