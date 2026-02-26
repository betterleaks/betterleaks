package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func OpenRouter() *config.Rule {
	r := config.Rule{
		RuleID:      "openrouter-api-key",
		Description: "Detected an OpenRouter API Key, which may expose access to multiple AI models through the OpenRouter gateway.",
		Regex:       utils.GenerateUniqueTokenRegex(`sk-or-v1-[0-9a-f]{64}`, true),
		Keywords:    []string{"sk-or-v1-"},
		Entropy:     3.5,
	}

	tps := utils.GenerateSampleSecrets("openrouter", "sk-or-v1-"+secrets.NewSecret(utils.Hex("64")))
	fps := []string{
		// Too short
		`sk-or-v1-0e6f44a47a05f1dad2ad7e88c4c1d6b7`,
		// Wrong prefix
		`sk-v1-0e6f44a47a05f1dad2ad7e88c4c1d6b77688157716fb1a5271146f7464951c96`,
	}
	return utils.Validate(r, tps, fps)
}
