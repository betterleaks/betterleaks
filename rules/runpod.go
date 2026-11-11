package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "runpod-api-key.1",
	Confidence:  "high",
	Description: "RunPod API key.",
	Regex:       Token(`rpa_[A-Z0-9]{40}[A-Za-z0-9]{6}`),
	Keywords:    []string{"rpa_"},
	ValidateExpr: `let r = http.post("https://api.runpod.io/graphql", {
    "Authorization": "Bearer " + finding["secret"],
    "Content-Type": "application/json",
    "Accept": "application/json"
  }, "{\"query\":\"{ myself { id } }\"}"); r.status == 200
    && (r.json?.data?.myself?.id ?? "") != "" ? {
    "result": "valid"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: MinEntropy(3.5),
	Tests: []config.RuleTest{
		Match("true positive 1", "RUNPOD_API_KEY=rpa_5FBBD6P84OE7UT4QRTTEBIWAR77S63DONNL8X7LIRFbD56", "rpa_5FBBD6P84OE7UT4QRTTEBIWAR77S63DONNL8X7LIRFbD56"),
		NoMatch("false positive 1", "RUNPOD_API_KEY=rpa_short"),
		NoMatch("false positive 2", "REDIRECT_PIZZA_TOKEN=rpa_Qj7mN4vK8sL2xP6zT9aBcD3eF5gH1j"),
	},
})
