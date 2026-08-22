package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func Mem0APIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "mem0-api-key.1",
		Confidence:  "high",
		Description: "Mem0 API key, which may allow access to stored application memories.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"mem0"}, `m0-[A-Za-z0-9]{24,44}`, false),
		Keywords:    []string{"mem0"},
		ValidateExpr: `let r = http.post("https://api.mem0.ai/v3/memories/?page=1&page_size=1", {
    "Authorization": "Token " + finding["secret"],
    "Accept": "application/json",
    "Content-Type": "application/json"
  }, "{\"filters\":{\"user_id\":\"betterleaks-validation\"}}"); r.status == 200 && (r.body contains "\"results\"") ? {
    "result": "valid"
  } : r.status == 401 && (r.body contains "Invalid API key") ? {
    "result": "invalid",
    "reason": "Invalid API key"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.0),
	}

	key := "m0-" + secrets.NewSecretWithEntropy(`[A-Za-z0-9]{32}`, 3.0)
	tps := []string{
		`MEM0_API_KEY=` + key,
		`mem0 token: "` + key + `"`,
	}
	fps := []string{
		`API_KEY=` + key,
		`MEM0_API_KEY=m0-short`,
		`MEM0_API_KEY=m0-00000000000000000000000000000000`,
	}
	return utils.Validate(r, tps, fps)
}
