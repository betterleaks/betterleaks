package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func Upstage() *config.Rule {
	r := config.Rule{
		RuleID:      "upstage-api-key",
		Description: "Detected an Upstage AI API key, which may expose Solar language models and document AI services to unauthorized access.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"upstage"}, `[A-Za-z0-9]{40,50}`, true),
		Keywords:    []string{"upstage"},
		Entropy:     3.5,
		ValidateCEL: `cel.bind(r,
  http.get("https://api.upstage.ai/v1/models", {
    "Authorization": "Bearer " + finding["secret"]
  }),
  r.status == 200 && r.body.contains('"data"') ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	}

	tps := utils.GenerateSampleSecrets("upstage", secrets.NewSecretWithEntropy(`[A-Za-z0-9]{40}`, 3.5))
	fps := []string{
		// Low entropy
		`upstage_token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`,
	}
	return utils.Validate(r, tps, fps)
}
