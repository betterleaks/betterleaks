package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	Description: "Identified a Bittrex Access Key, which could lead to unauthorized access to cryptocurrency trading accounts and financial loss.",
	ID:          "bittrex-access-key",
	Confidence:  "high",
	Regex:       rulebuilder.Assignment([]string{"bittrex"}, `(?i)`+rulebuilder.AlphaNumeric("32")),
	Keywords:    []string{"bittrex"},
	FilterExpr:  `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `bittrexToken = "5fbbd6p84oe7ut4qrttebiwar77s63do"`, "5fbbd6p84oe7ut4qrttebiwar77s63do"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	Description: "Detected a Bittrex Secret Key, potentially compromising cryptocurrency transactions and financial security.",
	ID:          "bittrex-secret-key",
	Confidence:  "high",
	Regex:       rulebuilder.Assignment([]string{"bittrex"}, `(?i)`+rulebuilder.AlphaNumeric("32")),
	Keywords:    []string{"bittrex"},
	FilterExpr:  `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `bittrexToken = "5fbbd6p84oe7ut4qrttebiwar77s63do"`, "5fbbd6p84oe7ut4qrttebiwar77s63do"),
	},
})
