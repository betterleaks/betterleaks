package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "cartesia-api-key.1",
	Confidence:  "high",
	Description: "Cartesia API key, which grants server-side access to Cartesia voice APIs.",
	Regex:       Token(`sk_car_[A-Za-z0-9_]{20}`),
	Keywords:    []string{"sk_car_"},
	ValidateExpr: `let r = http.get("https://api.cartesia.ai/voices?limit=1", {
    "Authorization": "Bearer " + finding["secret"],
    "Cartesia-Version": "2025-04-16",
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: MinEntropy(3.5),
	Tests: []config.RuleTest{
		Match("true positive 1", "CARTESIA_API_KEY=sk_car_eoTtDxpQ4FWYcbMq0Kt5", "sk_car_eoTtDxpQ4FWYcbMq0Kt5"),
		Match("true positive 2", "Authorization: Bearer sk_car_eoTtDxpQ4FWYcbMq0Kt5", "sk_car_eoTtDxpQ4FWYcbMq0Kt5"),
		NoMatch("false positive 1", "CARTESIA_API_KEY=sk_car_short"),
		NoMatch("false positive 2", "CARTESIA_API_KEY=sk_car_00000000000000000000"),
	},
})
