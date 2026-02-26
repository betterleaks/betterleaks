package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func Groq() *config.Rule {
	r := config.Rule{
		RuleID:      "groq-api-key",
		Description: "Identified a Groq API Key, which may expose high-speed AI inference services to unauthorized access.",
		Regex:       utils.GenerateUniqueTokenRegex(`gsk_[A-Z0-9]{52}`, true),
		Keywords:    []string{"gsk_"},
		Entropy:     3.5,
	}

	tps := utils.GenerateSampleSecrets("groq", "gsk_"+secrets.NewSecret(`[A-Z0-9]{52}`))
	fps := []string{
		// Too short
		`gsk_OpUMIkmFs2bOf1YRGh0lWGdy`,
	}
	return utils.Validate(r, tps, fps)
}
