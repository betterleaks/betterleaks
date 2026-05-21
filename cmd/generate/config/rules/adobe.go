package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func AdobeClientID() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "adobe-client-id",
		Description: "Detected a pattern that resembles an Adobe OAuth Web Client ID, posing a risk of compromised Adobe integrations and data breaches.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"adobe"}, utils.Hex("32"), true),
		Keywords:    []string{"adobe"},
		Filter: `entropy(finding["secret"]) <= 2.0`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("adobe", secrets.NewSecretWithEntropy(utils.Hex("32"), 2))
	return utils.Validate(r, tps, nil)
}

func AdobeClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "adobe-client-secret",
		Description: "Discovered a potential Adobe Client Secret, which, if exposed, could allow unauthorized Adobe service access and data manipulation.",
		Regex:       utils.GenerateUniqueTokenRegex(`p8e-(?i)[a-z0-9]{32}`, false),
		Keywords:    []string{"p8e-"},
		Filter: `entropy(finding["secret"]) <= 2.0`,
	}

	// validate
	tps := []string{
		"adobeClient := \"p8e-" + secrets.NewSecretWithEntropy(utils.Hex("32"), 2) + "\"",
	}
	return utils.Validate(r, tps, nil)
}
