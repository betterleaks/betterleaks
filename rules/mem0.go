package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "mem0-api-key.1",
	Confidence:  "high",
	Description: "Mem0 API key, which may allow access to stored application memories.",
	Regex:       rulebuilder.Assignment([]string{"mem0"}, `m0-[A-Za-z0-9]{24,44}`),
	Keywords:    []string{"mem0"},
	ValidateExpr: `let r = http.post("https://api.mem0.ai/v3/memories/?page=1&page_size=1", {
    "Authorization": "Token " + finding["secret"],
    "Accept": "application/json",
    "Content-Type": "application/json"
  }, "{\"filters\":{\"user_id\":\"betterleaks-validation\"}}"); r.status == 200 && (r.body contains "\"results\"") ? {
    "result": "valid"
  } : r.status == 401 && (r.body contains "Invalid API key") ? {
    "result": "invalid",
    "reason": "Invalid API key"
  } : validate.unknown(r)`,
	FilterExpr: rulebuilder.MinEntropy(3.0),
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "MEM0_API_KEY=m0-RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA", "m0-RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA"),
		rulebuilder.Match("true positive 2", `mem0 token: "m0-RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA"`, "m0-RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA"),
		rulebuilder.NoMatch("false positive 1", "API_KEY=m0-RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA"),
		rulebuilder.NoMatch("false positive 2", "MEM0_API_KEY=m0-short"),
		rulebuilder.NoMatch("false positive 3", "MEM0_API_KEY=m0-00000000000000000000000000000000"),
	},
})
