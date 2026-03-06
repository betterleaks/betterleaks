package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func SendGridAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "sendgrid-api-token",
		Description: "Detected a SendGrid API token, posing a risk of unauthorized email service operations and data exposure.",
		Regex:       utils.GenerateUniqueTokenRegex(`SG\.(?i)[a-z0-9=_\-\.]{66}`, false),
		Entropy:     2,
		Keywords: []string{
			"SG.",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("sengridAPIToken", "SG."+secrets.NewSecretWithEntropy(utils.AlphaNumericExtended("66"), 2))
	return utils.Validate(r, tps, nil)
}
