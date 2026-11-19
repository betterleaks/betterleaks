package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "new-relic-user-api-key",
	Confidence:  "high",
	Description: "Discovered a New Relic user API Key, which could lead to compromised application insights and performance monitoring.",
	Regex:       rulebuilder.Assignment([]string{"new-relic", "newrelic", "new_relic"}, `(?i)NRAK-[a-z0-9]{27}`),
	Keywords: []string{
		"nrak",
	},
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `new-relicToken = "NRAK-5fbbd6p84oe7ut4qrttebiwar77"`, "NRAK-5fbbd6p84oe7ut4qrttebiwar77"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "new-relic-user-api-id",
	Confidence:  "high",
	Description: "Found a New Relic user API ID, posing a risk to application monitoring services and data integrity.",
	Regex: rulebuilder.Assignment(
		[]string{
			"new-relic",
			"newrelic",
			"new_relic",
		},
		`(?i)[a-z0-9]{64}`,
	),
	Keywords: []string{
		"new-relic",
		"newrelic",
		"new_relic",
	},
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `new-relicToken = "5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7nz6lc"`, "5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7nz6lc"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "new-relic-browser-api-token",
	Confidence:  "high",
	Description: "Identified a New Relic ingest browser API token, risking unauthorized access to application performance data and analytics.",
	Regex:       rulebuilder.Assignment([]string{"new-relic", "newrelic", "new_relic"}, `(?i)NRJS-[a-f0-9]{19}`),
	Keywords: []string{
		"nrjs-",
	},
	FilterExpr: `entropy(finding["secret"]) < 3.0 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `new-relicToken = "NRJS-1f7b169c846f218ab55"`, "NRJS-1f7b169c846f218ab55"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "new-relic-insert-key",
	Confidence:  "high",
	Description: "Discovered a New Relic insight insert key, compromising data injection into the platform.",
	Regex:       rulebuilder.Assignment([]string{"new-relic", "newrelic", "new_relic"}, `(?i)NRII-[a-z0-9-]{32}`),
	Keywords: []string{
		"nrii-",
	},
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `new-relicToken = "NRII-bf5c97d2d2a313e4f95957818a7b3edc"`, "NRII-bf5c97d2d2a313e4f95957818a7b3edc"),
	},
})
