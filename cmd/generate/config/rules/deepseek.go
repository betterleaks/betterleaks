package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func DeepSeek() *config.Rule {
	r := config.Rule{
		RuleID:      "deepseek-api-key",
		Description: "Detected a DeepSeek API Key, which may expose AI model access and associated usage to unauthorized parties.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"deepseek"}, `sk-[a-f0-9]{32}`, true),
		Keywords:    []string{"deepseek"},
		Entropy:     3.5,
		ValidateCEL: `cel.bind(r,
  http.get("https://api.deepseek.com/models", {
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

	tps := utils.GenerateSampleSecrets("deepseek", "sk-"+secrets.NewSecretWithEntropy(utils.Hex("32"), 3.5))
	fps := []string{
		// Too short
		`deepseek_key = sk-ba588036180d4d1d9cebbf`,
		// All zeros (low entropy)
		`deepseek_key = sk-00000000000000000000000000000000`,
	}
	return utils.Validate(r, tps, fps)
}
