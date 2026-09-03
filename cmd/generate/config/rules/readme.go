package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

func ReadMe() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "readme-api-token",
		Confidence:  "high",
		Description: "Detected a Readme API token, risking unauthorized documentation management and content exposure.",
		Regex:       utils.GenerateUniqueTokenRegex(`rdme_[a-z0-9]{70}`, false),
		Keywords: []string{
			"rdme_",
		},
		Filter: `entropy(finding["secret"]) <= 2.0`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("api-token", "rdme_"+secrets.NewSecretWithEntropy(utils.AlphaNumeric("70"), 2))

	fps := []string{
		`const API_KEY = 'rdme_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX';`,
	}
	return utils.Validate(r, tps, fps)
}
