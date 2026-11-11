package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "minimax-api-key",
	Confidence:  "high",
	Description: "Detected a MiniMax API key, which may expose AI model, speech, image, video, or file services to unauthorized access.",
	Regex:       Token(`(?i)sk-api-[A-Za-z0-9_-]{119}`),
	Keywords:    []string{"sk-api-", "minimax"},
	ValidateExpr: `let r = http.get("https://api.minimax.io/v1/models", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 && (r.body contains '"data"') ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) <= 3.5`,
	Tests: []config.RuleTest{
		Match("minimax assignment", `minimaxToken = "sk-api-WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG7ubf2TxReZd1UXAceqba86woUt0S8fdI2myN1nZ6NYCy0bQx6umpyk9dz5c02tM"`, "sk-api-WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG7ubf2TxReZd1UXAceqba86woUt0S8fdI2myN1nZ6NYCy0bQx6umpyk9dz5c02tM"),
		NoMatch("false positive 1", `minimax_api_key = "sk-api-uBf3S6jw9Akw0X6u9KDy"`),
		NoMatch("false positive 2", `minimax_api_key = "sk-api-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`),
		NoMatch("false positive 3", `minimax_api_key = "sk-uBf3S6jw9Akw0X6u9KDygGb5rDn1LdZ7G3mVtvHhQb7x0sMn"`),
	},
})
