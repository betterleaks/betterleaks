package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "mistral-api-key",
	Confidence:  "medium",
	Description: "Detected a Mistral AI API Key, which may expose AI language model services to unauthorized access.",
	Regex:       Assignment([]string{"mistral"}, `(?i)[A-Z0-9]{32}`),
	Keywords:    []string{"mistral"},
	ValidateExpr: `let r = http.get("https://api.mistral.ai/v1/models", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 && (r.body contains '"data"') ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("mistral assignment", `mistralToken = "5FBBD6P84OE7UT4QRTTEBIWAR77S63DO"`, "5FBBD6P84OE7UT4QRTTEBIWAR77S63DO"),
		NoMatch("Too short", "mistral_token = 47cFZMzkoEo9DBapfvhrmMst3zfV"),
		NoMatch("All same chars (low entropy)", "mistral_token = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
	},
})
