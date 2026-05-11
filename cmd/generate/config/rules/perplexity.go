package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func PerplexityAPIKey() *config.Rule {
	// Define Rule
	r := config.Rule{
		RuleID:      "perplexity-api-key",
		Description: "Detected a Perplexity API key, which could lead to unauthorized access to Perplexity AI services and data exposure.",
		Regex:       regexp.MustCompile(`\b(pplx-[a-zA-Z0-9]{48})(?:[\x60'"\s;]|\\[nr]|$|\b)`),
		Keywords:    []string{"pplx-"},
		Entropy:     4.0,
		ValidateCEL: `cel.bind(r,
  http.post("https://api.perplexity.ai/chat/completions", {
    "Authorization": "Bearer " + finding["secret"],
    "Content-Type": "application/json"
  }, "{\"model\":\"invalid-model-for-validation\",\"messages\":[{\"role\":\"user\",\"content\":\".\"}]}"),
  r.status in [200, 400, 404, 422] ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("perplexity", "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'")
	fps := []string{
		"PERPLEXITY_API_KEY=pplx-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	}
	return utils.Validate(r, tps, fps)
}
