package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func mistralValidation() *config.Validation {
	return &config.Validation{
		Type:   config.ValidationTypeHTTP,
		Method: "GET",
		URL:    "https://api.mistral.ai/v1/models",
		Headers: map[string]string{
			"Authorization": "Bearer {{ secret }}",
			"Accept":        "application/json",
		},
		Match: []config.MatchClause{
			{StatusCodes: []int{200}, Words: []string{`"data"`}, Result: "valid"},
			{StatusCodes: []int{401, 403}, Result: "invalid"},
		},
	}
}

func Mistral() *config.Rule {
	r := config.Rule{
		RuleID:      "mistral-api-key",
		Description: "Detected a Mistral AI API Key, which may expose AI language model services to unauthorized access.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"mistral"}, `[A-Z0-9]{32}`, true),
		Keywords:    []string{"mistral"},
		Entropy:     3.0,
		Validation:  mistralValidation(),
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
