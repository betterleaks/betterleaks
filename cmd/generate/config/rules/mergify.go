package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func MergifyApplicationKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "mergify-application-key",
		Description: "Mergify application API key.",
		Regex:       utils.GenerateUniqueTokenRegex(`mergify_application_key_[A-Za-z0-9_-]{40,200}`, false),
		Keywords:    []string{"mergify_application_key_"},
		ValidateExpr: `let r = http.get("https://api.mergify.com/v1/application", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 && (r.body contains "\"id\"") && (r.body contains "\"name\"") && (r.body contains "\"scope\"") ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.2),
	}

	// validate
	tps := []string{
		"MERGIFY_API_KEY=mergify_application_key_" + secrets.NewSecretWithEntropy(`[A-Za-z0-9_-]{64}`, 3.2),
	}
	fps := []string{
		`MERGIFY_API_KEY=mergify_application_key_short`,
		`MERGIFY_API_KEY=mergify_application_key_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`,
	}
	return utils.Validate(r, tps, fps)
}
