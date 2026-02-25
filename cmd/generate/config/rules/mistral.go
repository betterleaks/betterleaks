package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func Mistral() *config.Rule {
	r := config.Rule{
		RuleID:      "mistral-api-key",
		Description: "Detected a Mistral AI API Key, which may expose AI language model services to unauthorized access.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"mistral"}, `[A-Z0-9]{32}`, true),
		Keywords:    []string{"mistral"},
		Entropy:     3.0,
	}

	tps := utils.GenerateSampleSecrets("mistral", secrets.NewSecret(`[A-Z0-9]{32}`))
	fps := []string{
		// Too short
		`mistral_token = 47cFZMzkoEo9DBapfvhrmMst3zfV`,
		// All same chars (low entropy)
		`mistral_token = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`,
	}
	return utils.Validate(r, tps, fps)
}
