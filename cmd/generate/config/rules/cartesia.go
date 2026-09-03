package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

func CartesiaAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "cartesia-api-key.1",
		Confidence:  "high",
		Description: "Cartesia API key, which grants server-side access to Cartesia voice APIs.",
		Regex:       utils.GenerateUniqueTokenRegex(`sk_car_[A-Za-z0-9_]{20}`, false),
		Keywords:    []string{"sk_car_"},
		ValidateExpr: `let r = http.get("https://api.cartesia.ai/voices?limit=1", {
    "Authorization": "Bearer " + finding["secret"],
    "Cartesia-Version": "2025-04-16",
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.5),
	}

	key := "sk_car_" + secrets.NewSecretWithEntropy(`[A-Za-z0-9_]{20}`, 3.5)
	tps := []string{
		`CARTESIA_API_KEY=` + key,
		`Authorization: Bearer ` + key,
	}
	fps := []string{
		`CARTESIA_API_KEY=sk_car_short`,
		`CARTESIA_API_KEY=sk_car_00000000000000000000`,
	}
	return utils.Validate(r, tps, fps)
}
