package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func XAI() *config.Rule {
	r := config.Rule{
		RuleID:      "xai-api-key",
		Description: "Detected an xAI (Grok) API Key, which may expose Grok AI model access to unauthorized parties.",
		Regex:       utils.GenerateUniqueTokenRegex(`xai-[A-Za-z0-9_-]{70,120}`, true),
		Keywords:    []string{"xai-"},
		Entropy:     3.5,
	}

	tps := utils.GenerateSampleSecrets("xai", "xai-"+secrets.NewSecret(`[A-Za-z0-9_-]{84}`))
	fps := []string{
		// Too short
		`xai-CNPlxZEZVpxDTRD8N6Luet7LwS2qyuijh7pdHbmNzsw`,
		// Wrong prefix
		`xbi-CNPlxZEZVpxDTRD8N6Luet7LwS2qyuijh7pdHbmNzswLAYSWUeODm8Cav2On1LqgrCewPvGCWxBqSbh3`,
	}
	return utils.Validate(r, tps, fps)
}
