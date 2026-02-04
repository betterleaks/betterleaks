package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
)

func MaxMindLicenseKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "maxmind-license-key",
		Description: "Discovered a potential MaxMind license key.",
		Regex:       utils2.GenerateUniqueTokenRegex(`[A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk`, false),
		Entropy:     4,
		Keywords:    []string{"_mmk"},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("maxmind", `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`) // gitleaks:allow
	return utils2.Validate(r, tps, nil)
}
