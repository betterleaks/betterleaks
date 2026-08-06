package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func RootlyAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "rootly-api-key.1",
		Description: "Rootly API key.",
		Regex:       utils.GenerateUniqueTokenRegex(`rootly_[a-f0-9]{64}`, false),
		Keywords:    []string{"rootly_"},
		ValidateExpr: `let r = http.get("https://api.rootly.com/v1/incidents", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status in [200, 404] ? {
    "result": "valid"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Invalid token"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.5),
	}

	// validate
	tps := []string{
		"ROOTLY_API_KEY=rootly_" + secrets.NewSecretWithEntropy(`[a-f0-9]{64}`, 3.5),
	}
	fps := []string{
		`ROOTLY_API_KEY=rootly_short`,
		`ROOTLY_API_KEY=rootly_0000000000000000000000000000000000000000000000000000000000000000`,
	}
	return utils.Validate(r, tps, fps)
}
