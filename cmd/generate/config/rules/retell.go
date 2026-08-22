package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func RetellAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "retell-api-key.1",
		Confidence:  "high",
		Description: "Retell AI API key, which may allow access to agents, calls, and account configuration.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"retell"}, `key_`+utils.Hex("28"), false),
		Keywords:    []string{"retell"},
		ValidateExpr: `let r = http.get("https://api.retellai.com/get-concurrency", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 && (r.body contains "\"current_concurrency\"") && (r.body contains "\"concurrency_limit\"") ? {
    "result": "valid"
  } : r.status == 401 && (r.body contains "Invalid API Key") ? {
    "result": "invalid",
    "reason": "Invalid API key"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.0),
	}

	key := "key_" + secrets.NewSecretWithEntropy(`[a-f0-9]{28}`, 3.0)
	tps := []string{
		`RETELL_API_KEY=` + key,
		`retell.ai token: "` + key + `"`,
	}
	fps := []string{
		`API_KEY=` + key,
		`RETELL_API_KEY=key_short`,
		`RETELL_API_KEY=key_0000000000000000000000000000`,
	}
	return utils.Validate(r, tps, fps)
}
