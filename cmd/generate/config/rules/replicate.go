package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func Replicate() *config.Rule {
	r := config.Rule{
		RuleID:      "replicate-api-token",
		Description: "Detected a Replicate API Token, which may expose AI model hosting and inference services to unauthorized access.",
		Regex:       utils.GenerateUniqueTokenRegex(`r8_[A-Za-z0-9]{37}`, true),
		Keywords:    []string{"r8_"},
		Entropy:     3.0,
		ValidateCEL: `cel.bind(r,
  http.get("https://api.replicate.com/v1/account", {
    "Authorization": "Bearer " + secret
  }),
  r.status == 200 && r.body.contains('"type"') && r.body.contains('"username"') && r.body.contains('"name"') ? {
    "result": "valid",
    "username": r.json.?username.orValue("")
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	}

	tps := utils.GenerateSampleSecrets("replicate", "r8_"+secrets.NewSecretWithEntropy(`[A-Za-z0-9]{37}`, 3.0))
	fps := []string{
		// Too short
		`r8_WesXNvqsCpq7r1gpQABpB3NJvdR`,
		// Wrong prefix
		`r9_WesXNvqsCpq7r1gpQABpB3NJvdR21nb2s7HVy`,
	}
	return utils.Validate(r, tps, fps)
}
