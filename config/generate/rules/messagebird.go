package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func MessageBirdAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Found a MessageBird API token, risking unauthorized access to communication platforms and message data.",
		RuleID:      "messagebird-api-token",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"message[_-]?bird"}, utils2.AlphaNumeric("25"), true),

		Keywords: []string{
			"messagebird",
			"message-bird",
			"message_bird",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("messagebird", secrets.NewSecret(utils2.AlphaNumeric("25")))
	tps = append(tps, utils2.GenerateSampleSecrets("message-bird", secrets.NewSecret(utils2.AlphaNumeric("25")))...)
	tps = append(tps, utils2.GenerateSampleSecrets("message_bird", secrets.NewSecret(utils2.AlphaNumeric("25")))...)
	return utils2.Validate(r, tps, nil)
}

func MessageBirdClientID() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discovered a MessageBird client ID, potentially compromising API integrations and sensitive communication data.",
		RuleID:      "messagebird-client-id",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"message[_-]?bird"}, utils2.Hex8_4_4_4_12(), true),

		Keywords: []string{
			"messagebird",
			"message-bird",
			"message_bird",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("MessageBird", "12345678-ABCD-ABCD-ABCD-1234567890AB") // gitleaks:allow
	tps = append(tps,
		`const MessageBirdClientID = "12345678-ABCD-ABCD-ABCD-1234567890AB"`, // gitleaks:allow
	)
	return utils2.Validate(r, tps, nil)
}
