package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

func XenditProductionAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "xendit-production-api-key.1",
		Confidence:  "high",
		Description: "Xendit production API key, which may allow access to payment and balance APIs.",
		Regex:       utils.GenerateUniqueTokenRegex(`xnd_production_[A-Za-z0-9]{56,72}`, false),
		Keywords:    []string{"xnd_production_"},
		ValidateExpr: `let r = http.get("https://api.xendit.co/balance", {
    "Authorization": "Basic " + base64.encode(bytes(finding["secret"] + ":")),
    "Accept": "application/json"
  }); r.status == 200 && (r.body contains "\"balance\"") ? {
    "result": "valid"
  } : r.status == 401 && (r.json?.error_code ?? "") == "INVALID_API_KEY" ? {
    "result": "invalid",
    "reason": "Invalid API key"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.0),
	}

	key := "xnd_production_" + secrets.NewSecretWithEntropy(`[A-Za-z0-9]{64}`, 3.0)
	tps := []string{
		`XENDIT_SECRET_KEY=` + key,
		`Authorization: Basic ` + key,
	}
	fps := []string{
		`XENDIT_SECRET_KEY=xnd_development_A1b2C3d4E5f6G7h8J9kLmNoPqRsTuVwXyZ0123456789AbCdEfGhJkLm`,
		`XENDIT_SECRET_KEY=xnd_production_short`,
		`XENDIT_SECRET_KEY=xnd_production_0000000000000000000000000000000000000000000000000000000000000000`,
	}
	return utils.Validate(r, tps, fps)
}
