package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "confluent-secret-key",
	Confidence:  "high",
	Description: "Found a Confluent Secret Key, potentially risking unauthorized operations and data access within Confluent services.",
	Regex:       Assignment([]string{"confluent"}, `(?i)`+AlphaNumeric("64")),
	Keywords: []string{
		"confluent",
	},
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("confluent assignment", `confluentToken = "5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7nz6lc"`, "5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7nz6lc"),
	},
})

var _ = Add(config.Rule{
	ID:          "confluent-access-token",
	Confidence:  "high",
	Description: "Identified a Confluent Access Token, which could compromise access to streaming data platforms and sensitive data flow.",
	Regex:       Assignment([]string{"confluent"}, `(?i)`+AlphaNumeric("16")),
	FilterExpr:  MinEntropyAndTokenEfficiency,

	Keywords: []string{
		"confluent",
	},
	Tests: []config.RuleTest{
		Match("confluent assignment", `confluentToken = "5fbbd6p84oe7ut4q"`, "5fbbd6p84oe7ut4q"),
	},
})
