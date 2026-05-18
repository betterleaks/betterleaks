package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func CastAI() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "castai-api-key",
		Description: "Identified a pattern that may indicate a Cast AI API key.",
		Regex:       regexp.MustCompile(`\b(castai_v1_[a-z0-9]{64}_[a-z0-9]{8})\b`),
		Entropy:     3,
		Keywords: []string{
			"castai_v1_", // Prefix
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("CastAI", "castai_v1_2cb5a70064f60ba2f5507bcbb02938a5a0483bf2a9742d08c5c274c827c9f6ea_aabb92b5")
	tps = append(tps, utils.GenerateSampleSecrets("CastAI", "castai_v1_"+secrets.NewSecret("[a-z0-9]{64}_[a-z0-9]{8}"))...)
	fps := []string{
		`key = test_v1_2cb5a70064f60ba2f5507bcbb02938a5a0483bf2a9742d08c5c274c827c9f6ea_037192b5`,
		`key = cast_v1_2cb5a70064f60ba2f5507bcxxxx`,
	}
	return utils.Validate(r, tps, fps)

}
