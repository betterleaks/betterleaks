package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "easypost-api-token",
	Confidence:  "high",
	Description: "Identified an EasyPost API token, which could lead to unauthorized postal and shipment service access and data exposure.",
	Regex:       `\bEZAK(?i)[a-z0-9]{54}\b`,
	Keywords:    []string{"ezak"},
	FilterExpr:  `entropy(finding["secret"]) <= 2.0`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `EZAKToken = "EZAKRFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klKiz9pyKl17ltL"`, "EZAKRFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klKiz9pyKl17ltL"),
		rulebuilder.Match("bare secret", "EZAKRFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klKiz9pyKl17ltL", "EZAKRFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klKiz9pyKl17ltL"),
		rulebuilder.Match("true positive 1", "example.com?t=EZAKRFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klKiz9pyKl17ltL&q=1", "EZAKRFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klKiz9pyKl17ltL"),
		rulebuilder.NoMatch("false positive 1", "...6wqX6fNUXA/rYqRvfQ+EZAKGqQRiRyqAFRQshGPWOIAwNWGORfKHSBnVNFtVmWYoW6PH23lkqbbDWep95C/3VmWq/edti6..."),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "easypost-test-api-token",
	Confidence:  "high",
	Description: "Detected an EasyPost test API token, risking exposure of test environments and potentially sensitive shipment data.",
	Regex:       `\bEZTK(?i)[a-z0-9]{54}\b`,
	Keywords:    []string{"eztk"},
	FilterExpr:  `entropy(finding["secret"]) <= 2.0`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `EZTKToken = "EZTKRFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klKiz9pyKl17ltL"`, "EZTKRFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klKiz9pyKl17ltL"),
		rulebuilder.Match("bare secret", "EZTKRFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klKiz9pyKl17ltL", "EZTKRFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klKiz9pyKl17ltL"),
		rulebuilder.Match("true positive 1", "example.com?t=EZTKRFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klKiz9pyKl17ltL&q=1", "EZTKRFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klKiz9pyKl17ltL"),
		rulebuilder.NoMatch("false positive 1", "...6wqX6fNUXA/rYqRvfQ+EZTKGqQRiRyqAFRQshGPWOIAwNWGORfKHSBnVNFtVmWYoW6PH23lkqbbDWep95C/3VmWq/edti6..."),
	},
})
