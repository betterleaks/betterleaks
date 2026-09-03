package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

func AdobeClientID() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "adobe-client-id",
		Confidence:  "high",
		Description: "Detected a pattern that resembles an Adobe OAuth Web Client ID, posing a risk of compromised Adobe integrations and data breaches.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"adobe"}, utils.Hex("32"), true),
		Keywords:    []string{"adobe"},
		Filter:      `filter.entropy(finding["secret"]) < 3.0 || filter.tokenRatio(finding["secret"]) >= 2.5`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("adobe", secrets.NewSecretWithEntropy(utils.Hex("32"), 3.0))
	return utils.Validate(r, tps, nil)
}

func AdobeClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "adobe-client-secret",
		Confidence:  "high",
		Description: "Discovered a potential Adobe Client Secret, which, if exposed, could allow unauthorized Adobe service access and data manipulation.",
		Regex:       utils.GenerateUniqueTokenRegex(`p8e-(?i)[a-z0-9]{32}`, false),
		Keywords:    []string{"p8e-"},
		Filter:      `filter.entropy(finding["secret"]) < 3.0`,
	}

	// validate
	tps := []string{
		"adobeClient := \"p8e-" + secrets.NewSecretWithEntropy(utils.Hex("32"), 3.0) + "\"",
	}
	return utils.Validate(r, tps, nil)
}
