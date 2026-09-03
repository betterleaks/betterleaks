package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

func HunterAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "hunter-api-key.1",
		Confidence:  "medium",
		Description: "Hunter API key, which may allow access to account and email intelligence data.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"hunter"}, utils.Hex("40"), false),
		Keywords:    []string{"hunter"},
		ValidateExpr: `let r = http.get("https://api.hunter.io/v2/account", {
    "X-API-KEY": finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 && (r.body contains "\"data\"") ? {
    "result": "valid"
  } : r.status == 401 && (r.body contains "authentication_failed") ? {
    "result": "invalid",
    "reason": "No user found for the API key"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.5),
	}

	key := secrets.NewSecretWithEntropy(`[a-f0-9]{40}`, 3.5)
	tps := []string{
		`HUNTER_API_KEY=` + key,
		`hunter key: "` + key + `"`,
	}
	fps := []string{
		`API_KEY=` + key,
		`HUNTER_API_KEY=test-api-key`,
		`HUNTER_API_KEY=0000000000000000000000000000000000000000`,
	}
	return utils.Validate(r, tps, fps)
}
