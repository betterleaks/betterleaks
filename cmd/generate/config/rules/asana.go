package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func AsanaClientID() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discovered a potential Asana Client ID, risking unauthorized access to Asana projects and sensitive task information.",
		RuleID:      "asana-client-id",
		Confidence:  "high",
		Regex:       utils.GenerateSemiGenericRegex([]string{"asana"}, utils.Numeric("16"), true),
		Keywords:    []string{"asana"},
		Filter:      `filter.entropy(finding["secret"]) < 2.75`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("asana", secrets.NewSecretWithEntropy(utils.Numeric("16"), 2.75))
	return utils.Validate(r, tps, nil)
}

func AsanaClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Identified an Asana Client Secret, which could lead to compromised project management integrity and unauthorized access.",
		RuleID:      "asana-client-secret",
		Confidence:  "high",
		Regex:       utils.GenerateSemiGenericRegex([]string{"asana"}, utils.AlphaNumeric("32"), true),

		Keywords: []string{"asana"},
		Filter:   `filter.entropy(finding["secret"]) < 3.5`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("asana", secrets.NewSecretWithEntropy(utils.AlphaNumeric("32"), 3.5))
	return utils.Validate(r, tps, nil)
}
