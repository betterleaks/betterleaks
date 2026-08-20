package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func OpsgenieAPIKey() *config.Rule {
	// Opsgenie supports US and EU service regions. Existing REST credentials
	// remain usable until the service's announced end-of-support date, so both
	// fixed provider hosts are checked before rejecting a key.
	r := config.Rule{
		RuleID:      "opsgenie-api-key.1",
		Confidence:  "high",
		Description: "Opsgenie API key, which may allow access to alerts, incidents, and account configuration.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"opsgenie"}, utils.Hex8_4_4_4_12(), true),
		Keywords:    []string{"opsgenie"},
		ValidateExpr: `let us = http.get("https://api.opsgenie.com/v2/account", {
    "Authorization": "GenieKey " + finding["secret"],
    "Accept": "application/json"
  }); us.status in [200, 403] ? {
    "result": "valid",
    "region": "us"
  } : (let eu = http.get("https://api.eu.opsgenie.com/v2/account", {
    "Authorization": "GenieKey " + finding["secret"],
    "Accept": "application/json"
  }); eu.status in [200, 403] ? {
    "result": "valid",
    "region": "eu"
  } : us.status == 401 && eu.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(eu))`,
		Filter: utils.MinEntropy(3.0),
	}

	key := secrets.NewSecretWithEntropy(utils.Hex8_4_4_4_12(), 3.0)
	tps := []string{
		`OPSGENIE_API_KEY=` + key,
		`opsgenie token: "` + key + `"`,
	}
	fps := []string{
		`API_KEY=` + key,
		`OPSGENIE_API_KEY=00000000-0000-0000-0000-000000000000`,
		`OPSGENIE_API_KEY=short`,
	}
	return utils.Validate(r, tps, fps)
}
