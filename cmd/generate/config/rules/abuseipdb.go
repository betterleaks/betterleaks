package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func AbuseIPDBAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "abuseipdb-api-key.1",
		Confidence:  "high",
		Description: "AbuseIPDB API key, which may allow access to IP reputation data and abuse-reporting APIs.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"abuseipdb"}, utils.Hex("80"), true),
		Keywords:    []string{"abuseipdb"},
		ValidateExpr: `let r = http.get("https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=1", {
    "Key": finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 && (r.body contains "\"ipAddress\"") ? {
    "result": "valid"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.5),
	}

	key := secrets.NewSecretWithEntropy(`[a-f0-9]{80}`, 3.5)
	tps := []string{
		`ABUSEIPDB_API_KEY=` + key,
		`abuseipdb token: "` + key + `"`,
	}
	fps := []string{
		`API_KEY=` + key,
		`ABUSEIPDB_API_KEY=short`,
		`ABUSEIPDB_API_KEY=00000000000000000000000000000000000000000000000000000000000000000000000000000000`,
	}
	return utils.Validate(r, tps, fps)
}
