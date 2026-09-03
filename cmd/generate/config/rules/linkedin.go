package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

func LinkedinClientID() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "linkedin-client-id",
		Confidence:  "medium",
		Description: "Found a LinkedIn Client ID, risking unauthorized access to LinkedIn integrations and professional data exposure.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"linked[_-]?in"}, utils.AlphaNumeric("14"), true),
		Keywords: []string{
			"linkedin",
			"linked_in",
			"linked-in",
		},
		Filter: utils.MinEntropyAndTokenEfficiency,
	}

	// validate
	tps := utils.GenerateSampleSecrets("linkedin", secrets.NewSecretWithEntropy(utils.AlphaNumeric("14"), 3))
	return utils.Validate(r, tps, nil)
}

func LinkedinClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "linkedin-client-secret",
		Confidence:  "medium",
		Description: "Discovered a LinkedIn Client secret, potentially compromising LinkedIn application integrations and user data.",
		Regex: utils.GenerateSemiGenericRegex([]string{
			"linked[_-]?in",
		}, utils.AlphaNumeric("16"), true),
		Keywords: []string{
			"linkedin",
			"linked_in",
			"linked-in",
		},
		Filter: utils.MinEntropyAndTokenEfficiency,
	}

	// validate
	tps := utils.GenerateSampleSecrets("linkedin", secrets.NewSecretWithEntropy(utils.AlphaNumeric("16"), 3))
	return utils.Validate(r, tps, nil)
}
