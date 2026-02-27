package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func TogetherAI() *config.Rule {
	r := config.Rule{
		RuleID:      "togetherai-api-key",
		Description: "Detected a Together.ai API Key, which may expose access to open-source AI models and inference services.",
		Regex:       utils.GenerateUniqueTokenRegex(`tgp_v1_[A-Za-z0-9_-]{43}`, true),
		Keywords:    []string{"tgp_v1_"},
		Entropy:     3.0,
	}

	tps := utils.GenerateSampleSecrets("togetherai", "tgp_v1_"+secrets.NewSecret(`[A-Za-z0-9_-]{43}`))
	fps := []string{
		// Too short
		`tgp_v1_Tctm6OfOeNkwLIKkyxJxUHIqNKx2AvFr`,
		// Wrong prefix
		`tgp_v2_Tctm6OfOeNkwLIKkyxJxUHIqNKx2AvFr65tQRIOMgzY`,
	}
	return utils.Validate(r, tps, fps)
}
