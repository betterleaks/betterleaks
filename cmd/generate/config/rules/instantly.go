package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

func InstantlyAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "instantly-api-key.1",
		Confidence:  "medium",
		Description: "Instantly API key, which may allow access to campaigns, accounts, leads, and analytics.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"instantly"}, `[A-Za-z0-9+/]{66}==`, false),
		Keywords:    []string{"instantly"},
		ValidateExpr: `let r = http.get("https://api.instantly.ai/api/v2/accounts?limit=1", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status == 402 ? {
    "result": "valid",
    "reason": "Authenticated but the workspace does not have an active paid plan"
  } : r.status == 401 && (r.body contains "Invalid authorization header or API key") ? {
    "result": "invalid",
    "reason": "Invalid API key"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.3),
	}

	key := secrets.NewSecretWithEntropy(`[A-Za-z0-9+/]{66}`, 3.3) + "=="
	tps := []string{
		`INSTANTLY_API_KEY=` + key,
		`instantly.ai token: "` + key + `"`,
	}
	fps := []string{
		`API_KEY=` + key,
		`INSTANTLY_API_KEY=short`,
		`INSTANTLY_API_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==`,
	}
	return utils.Validate(r, tps, fps)
}
