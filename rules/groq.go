package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "groq-api-key",
	Confidence:  "high",
	Description: "Identified a Groq API Key, which may expose high-speed AI inference services to unauthorized access.",
	Regex:       Token(`(?i)gsk_[A-Z0-9]{52}`),
	Keywords:    []string{"gsk_"},
	ValidateExpr: `let r = http.get("https://api.groq.com/openai/v1/models", {
    "Authorization": "Bearer " + finding["secret"]
  }); r.status == 200 && (r.body contains '"id"') && (r.body contains '"data"') ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) <= 3.5`,
	Tests: []config.RuleTest{
		Match("groq assignment", `groqToken = "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"`, "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"),
		NoMatch("Too short", "gsk_OpUMIkmFs2bOf1YRGh0lWGdy"),
	},
})
