package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func DeepSeek() *config.Rule {
	r := config.Rule{
		RuleID:      "deepseek-api-key",
		Description: "Detected a DeepSeek API Key, which may expose AI model access and associated usage to unauthorized parties.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"deepseek"}, `sk-[a-f0-9]{32}`, true),
		Keywords:    []string{"deepseek"},
		Entropy:     3.7,
	}

	tps := utils.GenerateSampleSecrets("deepseek", "sk-"+secrets.NewSecret(utils.Hex("32")))
	fps := []string{
		// Too short
		`deepseek_key = sk-ba588036180d4d1d9cebbf`,
		// All zeros (low entropy)
		`deepseek_key = sk-00000000000000000000000000000000`,
	}
	return utils.Validate(r, tps, fps)
}
