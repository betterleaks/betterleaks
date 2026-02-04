package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func FinicityClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Identified a Finicity Client Secret, which could lead to compromised financial service integrations and data breaches.",
		RuleID:      "finicity-client-secret",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"finicity"}, utils2.AlphaNumeric("20"), true),

		Keywords: []string{"finicity"},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("finicity", secrets.NewSecret(utils2.AlphaNumeric("20")))
	return utils2.Validate(r, tps, nil)
}

func FinicityAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Detected a Finicity API token, potentially risking financial data access and unauthorized financial operations.",
		RuleID:      "finicity-api-token",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"finicity"}, utils2.Hex("32"), true),

		Keywords: []string{"finicity"},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("finicity", secrets.NewSecret(utils2.Hex("32")))
	return utils2.Validate(r, tps, nil)
}
