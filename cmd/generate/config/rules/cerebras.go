package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func cerebrasValidation() *config.Validation {
	return &config.Validation{
		Type:   config.ValidationTypeHTTP,
		Method: "GET",
		URL:    "https://api.cerebras.ai/v1/models",
		Headers: map[string]string{
			"Authorization": "Bearer {{ secret }}",
		},
		Match: []config.MatchClause{
			{StatusCodes: []int{200}, Words: []string{`"object"`, `"data"`}, WordsAll: true, Result: "confirmed"},
			{StatusCodes: []int{401, 403}, Result: "invalid"},
			{Result: "unknown"},
		},
	}
}

func Cerebras() *config.Rule {
	r := config.Rule{
		RuleID:      "cerebras-api-key",
		Description: "Identified a Cerebras AI API Key, which may expose AI inference services to unauthorized access.",
		Regex:       utils.GenerateUniqueTokenRegex(`csk-[a-z0-9]{48}`, true),
		Keywords:    []string{"csk-"},
		Entropy:     3.0,
		Validation:  cerebrasValidation(),
	}

	tps := utils.GenerateSampleSecrets("cerebras", "csk-"+secrets.NewSecret(utils.AlphaNumeric("48")))
	fps := []string{
		// Too short
		`csk-6nptf4w5cx36fw58t3hkx`,
		// Wrong prefix
		`bsk-6nptf4w5cx36fw58t3hkx48jvm52wm693pex5tjm29kn55yt`,
	}
	return utils.Validate(r, tps, fps)
}
