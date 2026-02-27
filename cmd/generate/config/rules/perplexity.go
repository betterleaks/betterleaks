package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func perplexityValidation() *config.Validation {
	return &config.Validation{
		Type:   config.ValidationTypeHTTP,
		Method: "POST",
		URL:    "https://api.perplexity.ai/chat/completions",
		Headers: map[string]string{
			"Authorization": "Bearer {{ secret }}",
			"Content-Type":  "application/json",
		},
		Body: `{"model":"invalid-model-for-validation","messages":[{"role":"user","content":"."}]}`,
		Match: []config.MatchClause{
			{StatusCodes: []int{401, 403}, Result: "invalid"},
			{StatusCodes: []int{200}, Result: "confirmed"},
			{StatusCodes: []int{400, 404, 422}, Result: "confirmed"},
			{Result: "unknown"},
		},
	}
}

func PerplexityAPIKey() *config.Rule {
	// Define Rule
	r := config.Rule{
		RuleID:      "perplexity-api-key",
		Description: "Detected a Perplexity API key, which could lead to unauthorized access to Perplexity AI services and data exposure.",
		Regex:       regexp.MustCompile(`\b(pplx-[a-zA-Z0-9]{48})(?:[\x60'"\s;]|\\[nr]|$|\b)`),
		Keywords:    []string{"pplx-"},
		Entropy:     4.0,
		Validation:  perplexityValidation(),
	}

	// validate
	tps := utils.GenerateSampleSecrets("perplexity", "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'")
	fps := []string{
		"PERPLEXITY_API_KEY=pplx-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	}
	return utils.Validate(r, tps, fps)
}
