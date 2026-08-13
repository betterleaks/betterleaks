package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func FinicityClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Identified a Finicity Client Secret, which could lead to compromised financial service integrations and data breaches.",
		RuleID:      "finicity-client-secret",
		Confidence:  "high",
		Regex:       utils.GenerateSemiGenericRegex([]string{"finicity"}, utils.AlphaNumeric("20"), true),

		Keywords: []string{"finicity"},
		Filter:   `filter.entropy(finding["secret"]) < 3.0`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("finicity", secrets.NewSecretWithEntropy(utils.AlphaNumeric("20"), 3.0))
	return utils.Validate(r, tps, nil)
}

func FinicityAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Detected a Finicity API token, potentially risking financial data access and unauthorized financial operations.",
		RuleID:      "finicity-api-token",
		Confidence:  "high",
		Regex:       utils.GenerateSemiGenericRegex([]string{"finicity"}, utils.Hex("32"), true),

		Keywords: []string{"finicity"},
		Filter:   `filter.entropy(finding["secret"]) < 3.3`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("finicity", secrets.NewSecretWithEntropy(utils.Hex("32"), 3.3))
	return utils.Validate(r, tps, nil)
}
