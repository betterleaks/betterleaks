package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "perplexity-api-key",
	Confidence:  "high",
	Description: "Detected a Perplexity API key, which could lead to unauthorized access to Perplexity AI services and data exposure.",
	Regex:       `\b(pplx-[a-zA-Z0-9]{48})(?:[\x60'"\s;]|\\[nr]|$|\b)`,
	Keywords:    []string{"pplx-"},
	ValidateExpr: `let r = http.post("https://api.perplexity.ai/chat/completions", {
    "Authorization": "Bearer " + finding["secret"],
    "Content-Type": "application/json"
  }, "{\"model\":\"invalid-model-for-validation\",\"messages\":[{\"role\":\"user\",\"content\":\".\"}]}"); r.status in [200, 400, 404, 422] ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) <= 4.0`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `perplexityToken = "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'"`, "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"),
		rulebuilder.NoMatch("false positive 1", "PERPLEXITY_API_KEY=pplx-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
	},
})
