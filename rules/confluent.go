package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "confluent-secret-key",
	Confidence:  "high",
	Description: "Found a Confluent Secret Key, potentially risking unauthorized operations and data access within Confluent services.",
	Regex:       rulebuilder.Assignment([]string{"confluent"}, `(?i)[a-z0-9]{64}`),
	Keywords: []string{
		"confluent",
	},
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `confluentToken = "5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7nz6lc"`, "5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7nz6lc"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "confluent-access-token",
	Confidence:  "high",
	Description: "Identified a Confluent Access Token, which could compromise access to streaming data platforms and sensitive data flow.",
	Regex:       rulebuilder.Assignment([]string{"confluent"}, `(?i)[a-z0-9]{16}`),
	FilterExpr:  rulebuilder.MinEntropyAndTokenEfficiency,
	Keywords: []string{
		"confluent",
	},
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `confluentToken = "5fbbd6p84oe7ut4q"`, "5fbbd6p84oe7ut4q"),
	},
})
