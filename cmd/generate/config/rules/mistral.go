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
		ValidateCEL: `cel.bind(r,
  http.get("https://api.mistral.ai/v1/models", {
    "Authorization": "Bearer " + secret,
    "Accept": "application/json"
  }),
  r.status == 200 && r.body.contains('"data"') ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	}

	tps := utils.GenerateSampleSecrets("mistral", secrets.NewSecretWithEntropy(`[A-Z0-9]{32}`, 3.0))
	fps := []string{
		// Too short
		`mistral_token = 47cFZMzkoEo9DBapfvhrmMst3zfV`,
		// All same chars (low entropy)
		`mistral_token = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`,
	}
	return utils.Validate(r, tps, fps)
}
