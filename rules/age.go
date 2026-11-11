package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	Description: "Discovered a potential Age encryption tool secret key, risking data decryption and unauthorized access to sensitive information.",
	ID:          "age-secret-key",
	Confidence:  "high",
	Regex:       `AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}`,
	Keywords:    []string{"AGE-SECRET-KEY-1"},
	Tests: []config.RuleTest{
		Match("age assignment", `ageToken = "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"`, "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"),
	},
})
