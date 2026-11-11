package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "mem0-api-key.1",
	Confidence:  "high",
	Description: "Mem0 API key, which may allow access to stored application memories.",
	Regex:       Assignment([]string{"mem0"}, `m0-[A-Za-z0-9]{24,44}`),
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
	FilterExpr: MinEntropy(3.0),
	Tests: []config.RuleTest{
		Match("true positive 1", "MEM0_API_KEY=m0-RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA", "m0-RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA"),
		Match("true positive 2", `mem0 token: "m0-RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA"`, "m0-RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA"),
		NoMatch("false positive 1", "API_KEY=m0-RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA"),
		NoMatch("false positive 2", "MEM0_API_KEY=m0-short"),
		NoMatch("false positive 3", "MEM0_API_KEY=m0-00000000000000000000000000000000"),
	},
})
