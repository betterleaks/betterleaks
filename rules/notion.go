package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(Notion())

func Notion() config.Rule {
	// Define the identifiers that match the Keywords
	identifiers := []string{"ntn_"}
	// Define the regex pattern for Notion API token
	secretRegex := `ntn_[0-9]{11}[A-Za-z0-9]{32}[A-Za-z0-9]{3}`
	regex := Token(secretRegex)
	r := config.Rule{
		Description: "Notion API token",
		ID:          "notion-api-token",
		Confidence:  "high",
		Regex:       regex,
		Keywords:    identifiers,
		FilterExpr:  `entropy(finding["secret"]) <= 4.0`,
	}
	r.Tests = []config.RuleTest{
		Match("bare secret", "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", "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"),
		Match("bare secret 2", "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", "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"),
		Match("bare secret 3", "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", "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"),
		NoMatch("false positive 1", "ntn_12345678901"),
		NoMatch("false positive 2", "ntn_123456789012345678901234567890123456789012345678901234567890"),
		NoMatch("false positive 3", "ntn_12345678901abc"),
	}
	return r
}
