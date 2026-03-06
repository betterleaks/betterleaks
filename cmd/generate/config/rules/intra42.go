package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func Intra42ClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Found a Intra42 client secret, which could lead to unauthorized access to the 42School API and sensitive data.",
		RuleID:      "intra42-client-secret",
		Regex:       utils.GenerateUniqueTokenRegex(`s-s4t2(?:ud|af)-(?i)[abcdef0123456789]{64}`, false),
		Entropy:     3,
		Keywords: []string{
			"intra",
			"s-s4t2ud-",
			"s-s4t2af-",
		},
	}

	// validate
	tps := []string{
		"clientSecret := \"s-s4t2ud-" + secrets.NewSecretWithEntropy(utils.Hex("64"), 3) + "\"",
		"clientSecret := \"s-s4t2af-" + secrets.NewSecretWithEntropy(utils.Hex("64"), 3) + "\"",
		"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", // gitleaks:allow
		"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", // gitleaks:allow
	}
	return utils.Validate(r, tps, nil)
}
