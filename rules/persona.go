package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "persona-production-api-key",
	Confidence:  "high",
	Description: "Persona production API key.",
	Regex:       rulebuilder.Token(`persona_production_[a-z0-9_-]{20,80}`),
	Keywords:    []string{"persona_production_"},
	ValidateExpr: `let r = http.get("https://api.withpersona.com/api/v1/accounts?page[size]=1", {
    "Authorization": "Bearer " + finding["secret"],
    "Persona-Version": "2023-01-05",
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status == 403 && len(r.json?.errors ?? []) > 0 ? {
    "result": "valid",
    "reason": "Authenticated but access is restricted"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: rulebuilder.MinEntropy(3.5),
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "PERSONA_API_KEY=persona_production_4v8l67z---wfu0y1vd_3l1cmfzxoud8e", "persona_production_4v8l67z---wfu0y1vd_3l1cmfzxoud8e"),
		rulebuilder.NoMatch("false positive 1", "PERSONA_API_KEY=persona_sandbox_abc123def456ghi789jkl012mno345pqr"),
		rulebuilder.NoMatch("false positive 2", "PERSONA_API_KEY=persona_production_short"),
	},
})
