package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func LightOn() *config.Rule {
	r := config.Rule{
		RuleID:      "lighton-paradigm-api-key",
		Description: "Detected a LightOn Paradigm API key, which may expose enterprise LLM services to unauthorized access.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"lighton", "paradigm"}, `[A-Za-z0-9_\-]{40,80}`, true),
		Keywords:    []string{"lighton", "paradigm"},
		Entropy:     3.5,
		ValidateCEL: `cel.bind(r,
  http.get("https://paradigm.lighton.ai/api/v2/models", {
    "Authorization": "Bearer " + finding["secret"]
  }),
  r.status == 200 && r.body.contains('"object"') ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	}

	tps := utils.GenerateSampleSecrets("paradigm", secrets.NewSecretWithEntropy(`[A-Za-z0-9_\-]{48}`, 3.5))
	tps = append(tps, utils.GenerateSampleSecrets("lighton", secrets.NewSecretWithEntropy(`[A-Za-z0-9_\-]{48}`, 3.5))...)
	fps := []string{
		// Low entropy
		`paradigm_token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`,
	}
	return utils.Validate(r, tps, fps)
}
