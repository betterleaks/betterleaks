package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	Description: "Uncovered a Snyk API token, potentially compromising software vulnerability scanning and code security.",
	ID:          "snyk-api-token",
	Confidence:  "high",
	Regex:       rulebuilder.Assignment([]string{"snyk[_.-]?(?:(?:api|oauth)[_.-]?)?(?:key|token)"}, `(?i)`+rulebuilder.Hex8_4_4_4_12()),
	Keywords:    []string{"snyk"},
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `snykToken = "12345678-ABCD-ABCD-ABCD-1234567890AB"`, "12345678-ABCD-ABCD-ABCD-1234567890AB"),
		rulebuilder.Match("true positive 1", `const SNYK_TOKEN = "12345678-ABCD-ABCD-ABCD-1234567890AB"`, "12345678-ABCD-ABCD-ABCD-1234567890AB"),
		rulebuilder.Match("true positive 2", `const SNYK_KEY = "12345678-ABCD-ABCD-ABCD-1234567890AB"`, "12345678-ABCD-ABCD-ABCD-1234567890AB"),
		rulebuilder.Match("true positive 3", `SNYK_TOKEN := "12345678-ABCD-ABCD-ABCD-1234567890AB"`, "12345678-ABCD-ABCD-ABCD-1234567890AB"),
		rulebuilder.Match("true positive 4", `SNYK_TOKEN ::= "12345678-ABCD-ABCD-ABCD-1234567890AB"`, "12345678-ABCD-ABCD-ABCD-1234567890AB"),
		rulebuilder.Match("true positive 5", `SNYK_TOKEN :::= "12345678-ABCD-ABCD-ABCD-1234567890AB"`, "12345678-ABCD-ABCD-ABCD-1234567890AB"),
		rulebuilder.Match("true positive 6", `SNYK_TOKEN ?= "12345678-ABCD-ABCD-ABCD-1234567890AB"`, "12345678-ABCD-ABCD-ABCD-1234567890AB"),
		rulebuilder.Match("true positive 7", `SNYK_API_KEY ?= "12345678-ABCD-ABCD-ABCD-1234567890AB"`, "12345678-ABCD-ABCD-ABCD-1234567890AB"),
		rulebuilder.Match("true positive 8", `SNYK_API_TOKEN = "12345678-ABCD-ABCD-ABCD-1234567890AB"`, "12345678-ABCD-ABCD-ABCD-1234567890AB"),
		rulebuilder.Match("true positive 9", `SNYK_OAUTH_TOKEN = "12345678-ABCD-ABCD-ABCD-1234567890AB"`, "12345678-ABCD-ABCD-ABCD-1234567890AB"),
	},
})
