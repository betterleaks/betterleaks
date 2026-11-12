package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "nvidia-api-key",
	Confidence:  "high",
	Description: "Detected an NVIDIA NIM API Key, which may expose AI inference and GPU cloud services to unauthorized access.",
	Regex:       rulebuilder.Token(`(?i)nvapi-[A-Z0-9_-]{60,70}`),
	Keywords:    []string{"nvapi-"},
	FilterExpr:  `entropy(finding["secret"]) <= 3.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `nvidiaToken = "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"`, "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"),
		rulebuilder.NoMatch("Too short", "nvapi-AFNjXAgQdLYwZo2zJJUKLMIE4zrPYAks"),
		rulebuilder.NoMatch("Wrong prefix", "nvkey-AFNjXAgQdLYwZo2zJJUKLMIE4zrPYAksXDqWRXI_0Js5FXKl8lcuj7cssX34Wem8"),
	},
})
