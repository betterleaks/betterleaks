package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func NvidiaAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "nvidia-api-key",
		Description: "Detected an NVIDIA NIM API Key, which may expose AI inference and GPU cloud services to unauthorized access.",
		Regex:       utils.GenerateUniqueTokenRegex(`nvapi-[A-Z0-9_-]{60,70}`, true),
		Keywords:    []string{"nvapi-"},
		Entropy:     3.5,
	}

	tps := utils.GenerateSampleSecrets("nvidia", "nvapi-"+secrets.NewSecret(`[A-Z0-9_-]{64}`))
	fps := []string{
		// Too short
		`nvapi-AFNjXAgQdLYwZo2zJJUKLMIE4zrPYAks`,
		// Wrong prefix
		`nvkey-AFNjXAgQdLYwZo2zJJUKLMIE4zrPYAksXDqWRXI_0Js5FXKl8lcuj7cssX34Wem8`,
	}
	return utils.Validate(r, tps, fps)
}
