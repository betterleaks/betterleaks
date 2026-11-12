package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "datastax-astra-application-token",
	Confidence:  "high",
	Description: "DataStax Astra application token.",
	Regex:       `\b(AstraCS:[A-Za-z0-9]{20,})`,
	Keywords:    []string{"astracs:"},
	ValidateExpr: `let r = http.get("https://api.astra.datastax.com/v2/tokens", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: rulebuilder.MinEntropy(4.0),
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", `datastax_api_token = "AstraCS:5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7li"`, "AstraCS:5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7li"),
		rulebuilder.NoMatch("false positive 1", "ASTRA_DB_APPLICATION_TOKEN=AstraCS:short"),
	},
})
