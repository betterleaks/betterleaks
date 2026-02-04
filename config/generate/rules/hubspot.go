package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func HubSpot() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Found a HubSpot API Token, posing a risk to CRM data integrity and unauthorized marketing operations.",
		RuleID:      "hubspot-api-key",
		Regex: utils2.GenerateSemiGenericRegex([]string{"hubspot"},
			`[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`, true),

		Keywords: []string{"hubspot"},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("hubspot", secrets.NewSecret(utils2.Hex8_4_4_4_12()))
	tps = append(tps,
		`const hubspotKey = "12345678-ABCD-ABCD-ABCD-1234567890AB"`, // gitleaks:allow
	)
	return utils2.Validate(r, tps, nil)
}
