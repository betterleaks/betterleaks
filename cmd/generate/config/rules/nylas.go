package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func NylasAPIKey() *config.Rule {
	// Current v3 API keys have a stable provider prefix and are bound to either
	// the US or EU data-residency API. Only two fixed Nylas hosts are contacted.
	r := config.Rule{
		RuleID:      "nylas-api-key.1",
		Confidence:  "high",
		Description: "Nylas API key, which may allow application-level access to connected email, calendar, and contact data.",
		Regex:       utils.GenerateUniqueTokenRegex(`nyk_[A-Za-z0-9]{67}`, false),
		Keywords:    []string{"nyk_"},
		ValidateExpr: `let us = http.get("https://api.us.nylas.com/v3/webhooks?limit=1", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); us.status in [200, 403] ? {
    "result": "valid",
    "region": "us"
  } : (let eu = http.get("https://api.eu.nylas.com/v3/webhooks?limit=1", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); eu.status in [200, 403] ? {
    "result": "valid",
    "region": "eu"
  } : us.status == 401 && eu.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(eu))`,
		Filter: utils.MinEntropy(3.5),
	}

	key := "nyk_" + secrets.NewSecretWithEntropy(`[A-Za-z0-9]{67}`, 3.5)
	tps := []string{
		`NYLAS_API_KEY=` + key,
		`Authorization: Bearer ` + key,
	}
	fps := []string{
		`NYLAS_API_KEY=nyk_short`,
		`NYLAS_API_KEY=nyk_0000000000000000000000000000000000000000000000000000000000000000000`,
		`NYLAS_API_KEY=` + secrets.NewSecretWithEntropy(`[A-Za-z0-9]{30}`, 3.5),
	}
	return utils.Validate(r, tps, fps)
}
