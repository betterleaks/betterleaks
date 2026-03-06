package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func Groq() *config.Rule {
	r := config.Rule{
		RuleID:      "groq-api-key",
		Description: "Identified a Groq API Key, which may expose high-speed AI inference services to unauthorized access.",
		Regex:       utils.GenerateUniqueTokenRegex(`gsk_[A-Z0-9]{52}`, true),
		Keywords:    []string{"gsk_"},
		Entropy:     3.5,
		ValidateCEL: `cel.bind(r,
  http.get("https://api.groq.com/openai/v1/models", {
    "Authorization": "Bearer " + secret
  }),
  r.status == 200 && r.body.contains('"id"') && r.body.contains('"data"') ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	}

	tps := utils.GenerateSampleSecrets("groq", "gsk_"+secrets.NewSecretWithEntropy(`[A-Z0-9]{52}`, 3.5))
	fps := []string{
		// Too short
		`gsk_OpUMIkmFs2bOf1YRGh0lWGdy`,
	}
	return utils.Validate(r, tps, fps)
}
