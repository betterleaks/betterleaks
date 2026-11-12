package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

// https://docs.private-ai.com/reference/latest/operation/metrics_metrics_get/
var _ = rulebuilder.Add(config.Rule{
	ID:          "privateai-api-token",
	Confidence:  "medium",
	Description: "Identified a PrivateAI Token, posing a risk of unauthorized access to AI services and data manipulation.",
	Regex:       rulebuilder.Assignment([]string{"private[_-]?ai"}, `[a-z0-9]{32}`),
	Keywords: []string{
		"privateai",
		"private_ai",
		"private-ai",
	},
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", `privateai_api_token = "5fbbd6p84oe7ut4qrttebiwar77s63do"`, "5fbbd6p84oe7ut4qrttebiwar77s63do"),
		rulebuilder.NoMatch("false positive 1", `const privateaiToken = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";`),
	},
})
