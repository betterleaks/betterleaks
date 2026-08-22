package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func VultrAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "vultr-api-key.1",
		Confidence:  "medium",
		Description: "Vultr API key, which may allow management of cloud account resources.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"vultr"}, utils.Hex("36"), true),
		Keywords:    []string{"vultr"},
		ValidateExpr: `let r = http.get("https://api.vultr.com/v2/account", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 && (r.body contains "\"account\"") ? {
    "result": "valid"
  } : r.status == 401 && (r.body contains "Invalid API token") ? {
    "result": "invalid",
    "reason": "Invalid API token"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.4),
	}

	key := secrets.NewSecretWithEntropy(`[a-f0-9]{36}`, 3.4)
	tps := []string{
		`VULTR_API_KEY=` + key,
		`vultr token: "` + key + `"`,
	}
	fps := []string{
		`API_KEY=` + key,
		`VULTR_API_KEY=short`,
		`VULTR_API_KEY=000000000000000000000000000000000000`,
	}
	return utils.Validate(r, tps, fps)
}
