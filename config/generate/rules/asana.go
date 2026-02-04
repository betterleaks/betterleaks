package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func AsanaClientID() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discovered a potential Asana Client ID, risking unauthorized access to Asana projects and sensitive task information.",
		RuleID:      "asana-client-id",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"asana"}, utils2.Numeric("16"), true),
		Keywords:    []string{"asana"},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("asana", secrets.NewSecret(utils2.Numeric("16")))
	return utils2.Validate(r, tps, nil)
}

func AsanaClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Identified an Asana Client Secret, which could lead to compromised project management integrity and unauthorized access.",
		RuleID:      "asana-client-secret",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"asana"}, utils2.AlphaNumeric("32"), true),

		Keywords: []string{"asana"},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("asana", secrets.NewSecret(utils2.AlphaNumeric("32")))
	return utils2.Validate(r, tps, nil)
}
