package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

func MessageBirdAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Found a MessageBird API token, risking unauthorized access to communication platforms and message data.",
		RuleID:      "messagebird-api-token",
		Confidence:  "high",
		Regex:       utils.GenerateSemiGenericRegex([]string{"message[_-]?bird"}, utils.AlphaNumeric("25"), true),

		Keywords: []string{
			"messagebird",
			"message-bird",
			"message_bird",
		},
		Filter: `filter.entropy(finding["secret"]) < 3.0 || filter.tokenRatio(finding["secret"]) >= 2.5`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("messagebird", secrets.NewSecretWithEntropy(utils.AlphaNumeric("25"), 3.0))
	tps = append(tps, utils.GenerateSampleSecrets("message-bird", secrets.NewSecretWithEntropy(utils.AlphaNumeric("25"), 3.0))...)
	tps = append(tps, utils.GenerateSampleSecrets("message_bird", secrets.NewSecretWithEntropy(utils.AlphaNumeric("25"), 3.0))...)
	return utils.Validate(r, tps, nil)
}

func MessageBirdClientID() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discovered a MessageBird client ID, potentially compromising API integrations and sensitive communication data.",
		RuleID:      "messagebird-client-id",
		Confidence:  "high",
		Regex:       utils.GenerateSemiGenericRegex([]string{"message[_-]?bird"}, utils.Hex8_4_4_4_12(), true),

		Keywords: []string{
			"messagebird",
			"message-bird",
			"message_bird",
		},
		Filter: `filter.entropy(finding["secret"]) < 3.3 || filter.tokenRatio(finding["secret"]) >= 2.5`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("MessageBird", "12345678-ABCD-ABCD-ABCD-1234567890AB") // gitleaks:allow
	tps = append(tps,
		`const MessageBirdClientID = "12345678-ABCD-ABCD-ABCD-1234567890AB"`, // gitleaks:allow
	)
	return utils.Validate(r, tps, nil)
}
