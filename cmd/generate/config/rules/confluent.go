package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func ConfluentSecretKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "confluent-secret-key",
		Confidence:  "high",
		Description: "Found a Confluent Secret Key, potentially risking unauthorized operations and data access within Confluent services.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"confluent"}, utils.AlphaNumeric("64"), true),
		Keywords: []string{
			"confluent",
		},
		Filter: `filter.entropy(finding["secret"]) < 3.5 || filter.tokenRatio(finding["secret"]) >= 2.5`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("confluent", secrets.NewSecretWithEntropy(utils.AlphaNumeric("64"), 3.5))
	return utils.Validate(r, tps, nil)
}

func ConfluentAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "confluent-access-token",
		Confidence:  "high",
		Description: "Identified a Confluent Access Token, which could compromise access to streaming data platforms and sensitive data flow.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"confluent"}, utils.AlphaNumeric("16"), true),
		Filter:      utils.MinEntropyAndTokenEfficiency,

		Keywords: []string{
			"confluent",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("confluent", secrets.NewSecretWithEntropy(utils.AlphaNumeric("16"), 3.0))
	return utils.Validate(r, tps, nil)
}
