package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

// https://hunter.io/api-documentation/v2#account
const hunterValidateExpr = `let r = http.get("https://api.hunter.io/v2/account", {
  "X-API-KEY": finding["secret"],
  "Accept": "application/json"
});
r.status == 200 && type(r.json) == "map" && type(r.json?.data) == "map" && (r.json?.data?.email ?? "") != "" ? {
  "result": "valid",
  "analysis": {
    "identity": {
      "email": string(r.json?.data?.email ?? ""),
      "name": trim((r.json?.data?.first_name ?? "") + " " + (r.json?.data?.last_name ?? ""))
    },
  }
} : r.status == 401 ? {
  "result": "invalid", "reason": "Unauthorized"
} : validate.unknown(r)`

const hunterAnalyzeExpr = identityOnlyAnalyzeExpr

func HunterAPIKey() *config.Rule {
	r := config.Rule{
		ID:           "hunter-api-key.1",
		Confidence:   "medium",
		Description:  "Hunter API key, which may allow access to account and email intelligence data.",
		Regex:        utils.GenerateSemiGenericRegex([]string{"hunter"}, utils.Hex("40"), false),
		Keywords:     []string{"hunter"},
		ValidateExpr: hunterValidateExpr,
		AnalyzeExpr:  hunterAnalyzeExpr,
		Filter:       utils.MinEntropy(3.5),
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
