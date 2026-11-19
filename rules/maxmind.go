package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "maxmind-license-key",
	Confidence:  "high",
	Description: "Discovered a potential MaxMind license key.",
	Regex:       rulebuilder.Token(`[A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk`),
	Keywords:    []string{"_mmk"},
	FilterExpr:  `entropy(finding["secret"]) <= 4.0`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `maxmindToken = "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"`, "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"),
	},
})
