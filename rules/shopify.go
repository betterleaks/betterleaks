package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "shopify-shared-secret",
	Confidence:  "high",
	Description: "Found a Shopify shared secret, posing a risk to application authentication and e-commerce platform security.",
	Regex:       `shpss_[a-fA-F0-9]{32}`,
	Keywords:    []string{"shpss_"},
	FilterExpr:  `entropy(finding["secret"]) <= 2.0`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `shopifyToken = "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"`, "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"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "shopify-access-token",
	Confidence:  "high",
	Description: "Uncovered a Shopify access token, which could lead to unauthorized e-commerce platform access and data breaches.",
	Regex:       `shpat_[a-fA-F0-9]{32}`,
	Keywords:    []string{"shpat_"},
	FilterExpr:  `entropy(finding["secret"]) <= 2.0`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `shopifyToken = "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"`, "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"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "shopify-custom-access-token",
	Confidence:  "high",
	Description: "Detected a Shopify custom access token, potentially compromising custom app integrations and e-commerce data security.",
	Regex:       `shpca_[a-fA-F0-9]{32}`,
	Keywords:    []string{"shpca_"},
	FilterExpr:  `entropy(finding["secret"]) <= 2.0`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `shopifyToken = "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"`, "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"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "shopify-private-app-access-token",
	Confidence:  "high",
	Description: "Identified a Shopify private app access token, risking unauthorized access to private app data and store operations.",
	Regex:       `shppa_[a-fA-F0-9]{32}`,
	Keywords:    []string{"shppa_"},
	FilterExpr:  `entropy(finding["secret"]) <= 2.0`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `shopifyToken = "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"`, "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"),
	},
})
