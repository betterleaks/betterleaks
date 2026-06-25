package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func MiniMaxAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "minimax-api-key",
		Description: "Detected a MiniMax API key, which may expose AI model, speech, image, video, or file services to unauthorized access.",
		Regex:       utils.GenerateUniqueTokenRegex(`sk-api-[A-Za-z0-9_-]{119}`, true),
		Keywords:    []string{"sk-api-", "minimax"},
		ValidateExpr: `let r = http.get("https://api.minimax.io/v1/models", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 && (r.body contains '"data"') ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
		Filter: `entropy(finding["secret"]) <= 3.5`,
	}

	tps := append(
		utils.GenerateSampleSecrets("minimax", "sk-api-"+secrets.NewSecretWithEntropy(`[A-Za-z0-9_-]{119}`, 3.5)),
	)
	fps := []string{
		`minimax_api_key = "sk-api-uBf3S6jw9Akw0X6u9KDy"`,
		`minimax_api_key = "sk-api-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`,
		`minimax_api_key = "sk-uBf3S6jw9Akw0X6u9KDygGb5rDn1LdZ7G3mVtvHhQb7x0sMn"`,
	}
	return utils.Validate(r, tps, fps)
}
