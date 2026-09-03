package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

func VirusTotalAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "virustotal-api-key.1",
		Confidence:  "high",
		Description: "VirusTotal API key, which may expose private submissions, intelligence, or account API access.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"virustotal"}, utils.Hex("64"), true),
		Keywords:    []string{"virustotal"},
		ValidateExpr: `let r = http.get("https://www.virustotal.com/api/v3/domains/google.com", {
    "x-apikey": finding["secret"],
    "Accept": "application/json"
  }); let errorCode = (r.json?.error?.code ?? "");
r.status == 200 && (r.body contains "\"data\"") ? {
  "result": "valid"
} : r.status == 403 && errorCode == "ForbiddenError" ? {
  "result": "valid",
  "reason": "Authenticated but operation is forbidden"
} : r.status == 401 && errorCode == "UserNotActiveError" ? {
  "result": "valid",
  "reason": "Authenticated inactive VirusTotal account"
} : r.status == 401 && errorCode == "WrongCredentialsError" ? {
  "result": "invalid",
  "reason": "Wrong credentials"
} : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.5),
	}

	key := secrets.NewSecretWithEntropy(`[a-f0-9]{64}`, 3.5)
	tps := []string{
		`VIRUSTOTAL_API_KEY=` + key,
		`virustotal x-apikey: "` + key + `"`,
	}
	fps := []string{
		`API_KEY=` + key,
		`VIRUSTOTAL_API_KEY=short`,
		`VIRUSTOTAL_API_KEY=0000000000000000000000000000000000000000000000000000000000000000`,
	}
	return utils.Validate(r, tps, fps)
}
