package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	Description: "Found a Intra42 client secret, which could lead to unauthorized access to the 42School API and sensitive data.",
	ID:          "intra42-client-secret",
	Confidence:  "high",
	Regex:       Token(`s-s4t2(?:ud|af)-(?i)[abcdef0123456789]{64}`),
	Keywords: []string{
		"intra",
		"s-s4t2ud-",
		"s-s4t2af-",
	},
	FilterExpr: `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		Match("true positive 1", `clientSecret := "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"`, "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"),
		Match("true positive 2", `clientSecret := "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"`, "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"),
		Match("bare secret", "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", "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"),
		Match("bare secret 2", "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", "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"),
	},
})
