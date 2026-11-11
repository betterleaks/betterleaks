package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	Description: "Identified a Bittrex Access Key, which could lead to unauthorized access to cryptocurrency trading accounts and financial loss.",
	ID:          "bittrex-access-key",
	Confidence:  "high",
	Regex:       Assignment([]string{"bittrex"}, `(?i)`+AlphaNumeric("32")),
	Keywords:    []string{"bittrex"},
	FilterExpr:  `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("bittrex assignment", `bittrexToken = "5fbbd6p84oe7ut4qrttebiwar77s63do"`, "5fbbd6p84oe7ut4qrttebiwar77s63do"),
	},
})

var _ = Add(config.Rule{
	Description: "Detected a Bittrex Secret Key, potentially compromising cryptocurrency transactions and financial security.",
	ID:          "bittrex-secret-key",
	Confidence:  "high",
	Regex:       Assignment([]string{"bittrex"}, `(?i)`+AlphaNumeric("32")),

	Keywords:   []string{"bittrex"},
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("bittrex assignment", `bittrexToken = "5fbbd6p84oe7ut4qrttebiwar77s63do"`, "5fbbd6p84oe7ut4qrttebiwar77s63do"),
	},
})
