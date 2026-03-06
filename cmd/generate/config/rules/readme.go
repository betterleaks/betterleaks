package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func ReadMe() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "readme-api-token",
		Description: "Detected a Readme API token, risking unauthorized documentation management and content exposure.",
		Regex:       utils.GenerateUniqueTokenRegex(`rdme_[a-z0-9]{70}`, false),
		Entropy:     2,
		Keywords: []string{
			"rdme_",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("api-token", "rdme_"+secrets.NewSecretWithEntropy(utils.AlphaNumeric("70"), 2))

	fps := []string{
		`const API_KEY = 'rdme_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX';`,
	}
	return utils.Validate(r, tps, fps)
}
