package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func LinkedinClientID() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "linkedin-client-id",
		Description: "Found a LinkedIn Client ID, risking unauthorized access to LinkedIn integrations and professional data exposure.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"linked[_-]?in"}, utils.AlphaNumeric("14"), true),
		Keywords: []string{
			"linkedin",
			"linked_in",
			"linked-in",
		},
		Filter: `entropy(finding["secret"]) <= 2.0`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("linkedin", secrets.NewSecretWithEntropy(utils.AlphaNumeric("14"), 2))
	return utils.Validate(r, tps, nil)
}

func LinkedinClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "linkedin-client-secret",
		Description: "Discovered a LinkedIn Client secret, potentially compromising LinkedIn application integrations and user data.",
		Regex: utils.GenerateSemiGenericRegex([]string{
			"linked[_-]?in",
		}, utils.AlphaNumeric("16"), true),
		Keywords: []string{
			"linkedin",
			"linked_in",
			"linked-in",
		},
		Filter: `entropy(finding["secret"]) <= 2.0`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("linkedin", secrets.NewSecretWithEntropy(utils.AlphaNumeric("16"), 2))
	return utils.Validate(r, tps, nil)
}
