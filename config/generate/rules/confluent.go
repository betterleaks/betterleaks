package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func ConfluentSecretKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "confluent-secret-key",
		Description: "Found a Confluent Secret Key, potentially risking unauthorized operations and data access within Confluent services.",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"confluent"}, utils2.AlphaNumeric("64"), true),
		Keywords: []string{
			"confluent",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("confluent", secrets.NewSecret(utils2.AlphaNumeric("64")))
	return utils2.Validate(r, tps, nil)
}

func ConfluentAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "confluent-access-token",
		Description: "Identified a Confluent Access Token, which could compromise access to streaming data platforms and sensitive data flow.",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"confluent"}, utils2.AlphaNumeric("16"), true),

		Keywords: []string{
			"confluent",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("confluent", secrets.NewSecret(utils2.AlphaNumeric("16")))
	return utils2.Validate(r, tps, nil)
}
