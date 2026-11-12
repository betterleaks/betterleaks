package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	Description: "Notion API token",
	ID:          "notion-api-token",
	Confidence:  "high",
	Regex:       rulebuilder.Token(`ntn_[0-9]{11}[A-Za-z0-9]{32}[A-Za-z0-9]{3}`),
	Keywords:    []string{"ntn_"},
	FilterExpr:  `entropy(finding["secret"]) <= 4.0`,
	Tests: []config.RuleTest{
		rulebuilder.Match("bare secret", "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", "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"),
		rulebuilder.Match("bare secret 2", "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", "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"),
		rulebuilder.Match("bare secret 3", "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", "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"),
		rulebuilder.NoMatch("false positive 1", "ntn_12345678901"),
		rulebuilder.NoMatch("false positive 2", "ntn_123456789012345678901234567890123456789012345678901234567890"),
		rulebuilder.NoMatch("false positive 3", "ntn_12345678901abc"),
	},
})
