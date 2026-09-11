package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func ClearbitAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:       "clearbit-api-key",
		Confidence:   "medium",
		Description:  "Discovered a Clearbit API key, which could lead to unauthorized access to company and person enrichment data.",
		Regex:        utils.GenerateSemiGenericRegex([]string{"clearbit"}, `[0-9a-z_]{35}`, true),
		Keywords:     []string{"clearbit"},
		ValidateExpr: utils.BearerGetValidationExpr("https://person.clearbit.com/v1/people/email/alex@alexmaccaw.com", "true"),
		Filter:       utils.MinEntropyAndTokenEfficiency,
	}

	// validate
	tps := utils.GenerateSampleSecrets("clearbit", secrets.NewSecretWithEntropy(`[0-9a-z_]{35}`, 3.0))
	return utils.Validate(r, tps, nil)
}
