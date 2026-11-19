package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	Description: "Discovered a potential Age encryption tool secret key, risking data decryption and unauthorized access to sensitive information.",
	ID:          "age-secret-key",
	Confidence:  "high",
	Regex:       `AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}`,
	Keywords:    []string{"age-secret-key-1"},
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `ageToken = "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"`, "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"),
	},
})
