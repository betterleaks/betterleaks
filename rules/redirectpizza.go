package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "redirect-pizza-api-token.1",
	Confidence:  "high",
	Description: "redirect.pizza API token.",
	Regex:       rulebuilder.Token(`rpa_[A-Za-z0-9]{30}`),
	Keywords:    []string{"rpa_"},
	ValidateExpr: `let r = http.get("https://redirect.pizza/api/v1/domains", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status == 401 && (r.json?.message ?? "") == "Unauthenticated." ? {
    "result": "invalid",
    "reason": "Unauthenticated"
  } : validate.unknown(r)`,
	FilterExpr: rulebuilder.MinEntropy(3.5),
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "REDIRECT_PIZZA_TOKEN=rpa_5fbbd6p84oe7ut4qrttebiwar77s63", "rpa_5fbbd6p84oe7ut4qrttebiwar77s63"),
		rulebuilder.NoMatch("false positive 1", "REDIRECT_PIZZA_TOKEN=rpa_short"),
		rulebuilder.NoMatch("false positive 2", "REDIRECT_PIZZA_TOKEN=rpa_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
		rulebuilder.NoMatch("false positive 3", "RUNPOD_API_KEY=rpa_ABC123DEF456GHI789JKL012MNO345PQR678STUVX9y2z7"),
	},
})
