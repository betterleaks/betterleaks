package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func Intra42ClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Found a Intra42 client secret, which could lead to unauthorized access to the 42School API and sensitive data.",
		RuleID:      "intra42-client-secret",
		Regex:       utils2.GenerateUniqueTokenRegex(`s-s4t2(?:ud|af)-(?i)[abcdef0123456789]{64}`, false),
		Entropy:     3,
		Keywords: []string{
			"intra",
			"s-s4t2ud-",
			"s-s4t2af-",
		},
	}

	// validate
	tps := []string{
		"clientSecret := \"s-s4t2ud-" + secrets.NewSecret(utils2.Hex("64")) + "\"",
		"clientSecret := \"s-s4t2af-" + secrets.NewSecret(utils2.Hex("64")) + "\"",
		"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", // gitleaks:allow
		"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", // gitleaks:allow
	}
	return utils2.Validate(r, tps, nil)
}
