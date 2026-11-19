package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "langchain-langsmith-personal-access-token",
	Confidence:  "high",
	Description: "LangSmith personal access token.",
	Regex:       `\b(lsv2_pt_[0-9a-fA-F]{32}_[0-9a-fA-F]{10})`,
	Keywords:    []string{"lsv2_pt_"},
	ValidateExpr: `let r = http.get("https://api.smith.langchain.com/api/v1/api-key/current", {
    "X-API-Key": finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: rulebuilder.MinEntropy(4.0),
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "LANGSMITH_API_KEY=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", "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"),
		rulebuilder.NoMatch("false positive 1", "LANGSMITH_API_KEY=lsv2_pt_short"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "langchain-langsmith-service-key",
	Confidence:  "high",
	Description: "LangSmith service API key.",
	Regex:       `\b(lsv2_sk_[0-9a-fA-F]{32}_[0-9a-fA-F]{10})`,
	Keywords:    []string{"lsv2_sk_"},
	ValidateExpr: `let r = http.get("https://api.smith.langchain.com/api/v1/orgs/current", {
    "X-API-Key": finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: rulebuilder.MinEntropy(4.0),
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "LANGSMITH_SERVICE_KEY=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", "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"),
		rulebuilder.NoMatch("false positive 1", "LANGSMITH_SERVICE_KEY=lsv2_sk_short"),
	},
})
