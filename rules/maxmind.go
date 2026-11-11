package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "maxmind-license-key",
	Confidence:  "high",
	Description: "Discovered a potential MaxMind license key.",
	Regex:       Token(`[A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk`),
	Keywords:    []string{"_mmk"},
	FilterExpr:  `entropy(finding["secret"]) <= 4.0`,
	Tests: []config.RuleTest{
		Match("maxmind assignment", `maxmindToken = "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"`, "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"),
	},
})
