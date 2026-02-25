package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func Ollama() *config.Rule {
	r := config.Rule{
		RuleID:      "ollama-api-key",
		Description: "Detected an Ollama API Key, which may expose local and hosted AI model serving to unauthorized access.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"ollama"}, `[a-f0-9]{32}\.[a-zA-Z0-9_-]{24}`, true),
		Keywords:    []string{"ollama"},
		Entropy:     3.5,
	}

	tps := utils.GenerateSampleSecrets("ollama", secrets.NewSecret(utils.Hex("32"))+"."+secrets.NewSecret(`[a-zA-Z0-9_-]{24}`))
	fps := []string{
		// Too short body
		`ollama key = 8bcdd9b4e28e4e1b8bf14a2eb8701220`,
		// Missing dot separator
		`ollama key = 8bcdd9b4e28e4e1b8bf14a2eb8701220QH5p5TU2BDwzHu5_RCtvJXsj`,
	}
	return utils.Validate(r, tps, fps)
}
