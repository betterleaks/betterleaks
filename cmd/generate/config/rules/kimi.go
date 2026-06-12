package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func KimiAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "kimi-api-key",
		Description: "Detected a Kimi API key, which may expose Moonshot AI model access and usage to unauthorized parties.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"kimi", "moonshot"}, `sk-[A-Za-z0-9_-]{48}`, true),
		Keywords:    []string{"kimi", "moonshot"},
		ValidateCEL: `cel.bind(r,
  http.get("https://api.moonshot.ai/v1/models", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }),
  r.status == 200 && r.body.contains('"data"') ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)
)`,
		Filter: `entropy(finding["secret"]) <= 3.5`,
	}

	tps := append(
		utils.GenerateSampleSecrets("kimi", "sk-"+secrets.NewSecretWithEntropy(`[A-Za-z0-9_-]{48}`, 3.5)),
		utils.GenerateSampleSecrets("moonshot", "sk-"+secrets.NewSecretWithEntropy(`[A-Za-z0-9_-]{48}`, 3.5))...,
	)
	fps := []string{
		`api_key = "sk-uBf3S6jw9Akw0X6u9KDygGb5rDn1LdZ7G3mVtvHhQb7x0sMn"`,
		`kimi_api_key = "sk-uBf3S6jw9Akw0X6u9KDy"`,
		`moonshot_api_key = "sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`,
	}
	return utils.Validate(r, tps, fps)
}
