package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func replicateValidation() *config.Validation {
	return &config.Validation{
		Type:   config.ValidationTypeHTTP,
		Method: "GET",
		URL:    "https://api.replicate.com/v1/account",
		Headers: map[string]string{
			"Authorization": "Bearer {{ secret }}",
		},
		Match: []config.MatchClause{
			{StatusCodes: []int{200}, Words: []string{`"type"`, `"username"`, `"name"`}, WordsAll: true, Result: "valid"},
			{StatusCodes: []int{401, 403}, Result: "invalid"},
		},
	}
}

func Replicate() *config.Rule {
	r := config.Rule{
		RuleID:      "replicate-api-token",
		Description: "Detected a Replicate API Token, which may expose AI model hosting and inference services to unauthorized access.",
		Regex:       utils.GenerateUniqueTokenRegex(`r8_[A-Za-z0-9]{37}`, true),
		Keywords:    []string{"r8_"},
		Entropy:     3.0,
		Validation:  replicateValidation(),
	}

	tps := utils.GenerateSampleSecrets("replicate", "r8_"+secrets.NewSecret(`[A-Za-z0-9]{37}`))
	fps := []string{
		// Too short
		`r8_WesXNvqsCpq7r1gpQABpB3NJvdR`,
		// Wrong prefix
		`r9_WesXNvqsCpq7r1gpQABpB3NJvdR21nb2s7HVy`,
	}
	return utils.Validate(r, tps, fps)
}
