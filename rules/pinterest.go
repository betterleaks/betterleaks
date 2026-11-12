package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "pinterest-access-token",
	Confidence:  "high",
	Description: "Pinterest access token.",
	Regex:       rulebuilder.Token(`pina_[A-Za-z0-9_-]{20,200}`),
	Keywords:    []string{"pina_"},
	ValidateExpr: `let r = http.get("https://api.pinterest.com/v5/user_account", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 && (r.body contains "\"username\"") ? {
    "result": "valid"
  } : r.status == 403 ? {
    "result": "valid",
    "reason": "Authenticated but user-account access is restricted"
  } : r.status == 401 && (r.json?.code ?? 0) == 2 ? {
    "result": "invalid",
    "reason": "Authentication failed"
  } : validate.unknown(r)`,
	FilterExpr: rulebuilder.MinEntropy(3.5),
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "PINTEREST_ACCESS_TOKEN=pina_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxH", "pina_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxH"),
		rulebuilder.NoMatch("false positive 1", "PINTEREST_ACCESS_TOKEN=pina_short"),
		rulebuilder.NoMatch("false positive 2", "PINTEREST_ACCESS_TOKEN=pina_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
	},
})
