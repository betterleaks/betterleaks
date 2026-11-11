package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "deepseek-api-key",
	Confidence:  "high",
	Description: "Detected a DeepSeek API Key, which may expose AI model access and associated usage to unauthorized parties.",
	Regex:       Assignment([]string{"deepseek"}, `(?i)sk-[a-f0-9]{32}`),
	Keywords:    []string{"deepseek"},
	ValidateExpr: `let r = http.get("https://api.deepseek.com/models", {
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
		Match("deepseek assignment", `deepseekToken = "sk-bf5c97d2d2a313e4f95957818a7b3edc"`, "sk-bf5c97d2d2a313e4f95957818a7b3edc"),
		NoMatch("Too short", "deepseek_key = sk-ba588036180d4d1d9cebbf"),
		NoMatch("All zeros (low entropy)", "deepseek_key = sk-00000000000000000000000000000000"),
	},
})
