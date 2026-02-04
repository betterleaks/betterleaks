package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func LinkedinClientID() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "linkedin-client-id",
		Description: "Found a LinkedIn Client ID, risking unauthorized access to LinkedIn integrations and professional data exposure.",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"linked[_-]?in"}, utils2.AlphaNumeric("14"), true),
		Entropy:     2,
		Keywords: []string{
			"linkedin",
			"linked_in",
			"linked-in",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("linkedin", secrets.NewSecret(utils2.AlphaNumeric("14")))
	return utils2.Validate(r, tps, nil)
}

func LinkedinClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "linkedin-client-secret",
		Description: "Discovered a LinkedIn Client secret, potentially compromising LinkedIn application integrations and user data.",
		Regex: utils2.GenerateSemiGenericRegex([]string{
			"linked[_-]?in",
		}, utils2.AlphaNumeric("16"), true),
		Entropy: 2,
		Keywords: []string{
			"linkedin",
			"linked_in",
			"linked-in",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("linkedin", secrets.NewSecret(utils2.AlphaNumeric("16")))
	return utils2.Validate(r, tps, nil)
}
