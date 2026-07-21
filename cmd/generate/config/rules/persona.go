package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func PersonaProductionAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "persona-production-api-key",
		Description: "Persona production API key.",
		Regex:       utils.GenerateUniqueTokenRegex(`persona_production_[a-z0-9_-]{20,80}`, false),
		Keywords:    []string{"persona_production_"},
		ValidateExpr: `let r = http.get("https://api.withpersona.com/api/v1/accounts?page[size]=1", {
    "Authorization": "Bearer " + finding["secret"],
    "Persona-Version": "2023-01-05",
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status == 403 && size(r.json?.errors ?? []) > 0 ? {
    "result": "valid",
    "reason": "Authenticated but access is restricted"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.5),
	}

	// validate
	tps := []string{
		"PERSONA_API_KEY=persona_production_" + secrets.NewSecretWithEntropy(`[a-z0-9_-]{32}`, 3.5),
	}
	fps := []string{
		`PERSONA_API_KEY=persona_sandbox_abc123def456ghi789jkl012mno345pqr`,
		`PERSONA_API_KEY=persona_production_short`,
	}
	return utils.Validate(r, tps, fps)
}
