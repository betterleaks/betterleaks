package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "togetherai-api-key",
	Confidence:  "high",
	Description: "Detected a Together.ai API Key, which may expose access to open-source AI models and inference services.",
	Regex:       Token(`(?i)tgp_v1_[A-Za-z0-9_-]{43}`),
	Keywords:    []string{"tgp_v1_"},
	ValidateExpr: `let r = http.get("https://api.together.xyz/v1/models", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 && (r.body contains '"id"') && (r.body contains '"object"') ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		Match("togetherai assignment", `togetheraiToken = "tgp_v1_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH9"`, "tgp_v1_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH9"),
		NoMatch("Too short", "tgp_v1_Tctm6OfOeNkwLIKkyxJxUHIqNKx2AvFr"),
		NoMatch("Wrong prefix", "tgp_v2_Tctm6OfOeNkwLIKkyxJxUHIqNKx2AvFr65tQRIOMgzY"),
	},
})
