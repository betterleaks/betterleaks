package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	Description: "Found a Scalingo API token, posing a risk to cloud platform services and application deployment security.",
	ID:          "scalingo-api-token",
	Confidence:  "high",
	Regex:       Token(`tk-us-[\w-]{48}`),
	Keywords:    []string{"tk-us-"},
	FilterExpr:  `entropy(finding["secret"]) <= 2.0`,
	Tests: []config.RuleTest{
		Match("scalingo assignment", `scalingoToken = "tk-us-4v8l67z---wfu0y1vd_3l1cmfzxoud8et6xy88z3pomb2z7e"`, "tk-us-4v8l67z---wfu0y1vd_3l1cmfzxoud8et6xy88z3pomb2z7e"),
		Match("true positive 1", `scalingo_api_token = "tk-us-loys7ib9yrxcys_ta2sq85mjar6lgcsspkd9x61s7h5epf_-"`, "tk-us-loys7ib9yrxcys_ta2sq85mjar6lgcsspkd9x61s7h5epf_-"),
	},
})
