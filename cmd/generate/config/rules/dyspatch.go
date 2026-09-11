package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func DyspatchAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "dyspatch-api-key",
		Confidence:  "high",
		Description: "Detected a Dyspatch API key, which could allow unauthorized access to transactional email templates and sending operations.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"dyspatch"}, `[A-Z0-9]{52}`, true),
		Keywords:    []string{"dyspatch"},
		ValidateExpr: `let r = http.get("https://api.dyspatch.io/templates", {
    "Accept": "application/vnd.dyspatch.2020.11+json",
    "Authorization": "Bearer " + finding["secret"]
  }); r.status == 200 && (r.body contains "\"limited_usage\"" || r.body contains "\"data\"") ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
		Filter: `entropy(finding["secret"]) <= 4.0`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("dyspatch", secrets.NewSecretWithEntropy(`[A-Z0-9]{52}`, 4.0))
	return utils.Validate(r, tps, nil)
}
