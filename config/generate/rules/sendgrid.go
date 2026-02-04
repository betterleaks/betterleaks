package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func SendGridAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "sendgrid-api-token",
		Description: "Detected a SendGrid API token, posing a risk of unauthorized email service operations and data exposure.",
		Regex:       utils2.GenerateUniqueTokenRegex(`SG\.(?i)[a-z0-9=_\-\.]{66}`, false),
		Entropy:     2,
		Keywords: []string{
			"SG.",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("sengridAPIToken", "SG."+secrets.NewSecret(utils2.AlphaNumericExtended("66")))
	return utils2.Validate(r, tps, nil)
}
