package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "zuplo-consumer-api-key.1",
	Confidence:  "high",
	Description: "Zuplo consumer API key.",
	Regex:       rulebuilder.Token(`zpka_[a-z0-9]{32}_[0-9a-f]{8}`),
	Keywords:    []string{"zpka_"},
	ValidateExpr: `let r = http.get("https://dev.zuplo.com/v1/who-am-i", {
    "Authorization": "Bearer " + finding["secret"],
    "x-api-key": finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Authorization failed"
  } : validate.unknown(r)`,
	FilterExpr: rulebuilder.MinEntropy(3.3),
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "ZUPLO_API_KEY=zpka_3e6c4f7d39954ca29353b7ab88589b64_de26cd55", "zpka_3e6c4f7d39954ca29353b7ab88589b64_de26cd55"),
		rulebuilder.Match("true positive 2", "ZUPLO_API_KEY=zpka_b3f94d8d3d4d4a6ea5c5b20d0a5bb407_18eb262b", "zpka_b3f94d8d3d4d4a6ea5c5b20d0a5bb407_18eb262b"),
		rulebuilder.NoMatch("false positive 1", "ZUPLO_API_KEY=zpka_short"),
		rulebuilder.NoMatch("false positive 2", "ZUPLO_API_KEY=zpka_00000000000000000000000000000000_00000000"),
	},
})
