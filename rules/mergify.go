package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "mergify-application-key",
	Confidence:  "high",
	Description: "Mergify application API key.",
	Regex:       rulebuilder.Token(`mergify_application_key_[A-Za-z0-9_-]{40,200}`),
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
	FilterExpr: rulebuilder.MinEntropy(3.2),
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "MERGIFY_API_KEY=mergify_application_key_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG7ubf2TxR", "mergify_application_key_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG7ubf2TxR"),
		rulebuilder.NoMatch("false positive 1", "MERGIFY_API_KEY=mergify_application_key_short"),
		rulebuilder.NoMatch("false positive 2", "MERGIFY_API_KEY=mergify_application_key_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
	},
})
