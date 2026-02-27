package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func StabilityAI() *config.Rule {
	r := config.Rule{
		RuleID:      "stability-ai-api-key",
		Description: "Detected a Stability AI API Key, which may expose AI image generation services to unauthorized access.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"stability"}, `sk-[A-Za-z0-9]{48}`, true),
		Keywords:    []string{"stability"},
		Entropy:     3.5,
	}

	tps := utils.GenerateSampleSecrets("stability", "sk-"+secrets.NewSecret(`[A-Za-z0-9]{48}`))
	fps := []string{
		// Too short
		`stability_key = sk-AnmgropvAII5XEoxVPjbnSMG3XhacEwhJlLh8`,
		// Low entropy (all same chars)
		`stability_key = sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`,
	}
	return utils.Validate(r, tps, fps)
}
