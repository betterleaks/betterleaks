package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	Description: "Uncovered a Sonar API token, potentially compromising software vulnerability scanning and code security.",
	ID:          "sonar-api-token",
	Confidence:  "high",
	Regex:       rulebuilder.Assignment([]string{"sonar[_.-]?(login|token)"}, "(?i)(?:squ_|sqp_|sqa_)?"+rulebuilder.AlphaNumericExtended("40")),
	Keywords:    []string{"sonar"},
	ValueGroup:  2,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `sonarToken = "12345678ABCDEFH1234567890ABCDEFH12345678"`, "12345678ABCDEFH1234567890ABCDEFH12345678"),
		rulebuilder.Match("true positive 1", `const SONAR_LOGIN = "12345678ABCDEFH1234567890ABCDEFH12345678"`, "12345678ABCDEFH1234567890ABCDEFH12345678"),
		rulebuilder.Match("true positive 2", `SONAR_LOGIN := "12345678ABCDEFH1234567890ABCDEFH12345678"`, "12345678ABCDEFH1234567890ABCDEFH12345678"),
		rulebuilder.Match("true positive 3", `SONAR.LOGIN ::= "12345678ABCDEFH1234567890ABCDEFH12345678"`, "12345678ABCDEFH1234567890ABCDEFH12345678"),
		rulebuilder.Match("true positive 4", `SONAR.LOGIN :::= "12345678ABCDEFH1234567890ABCDEFH12345678"`, "12345678ABCDEFH1234567890ABCDEFH12345678"),
		rulebuilder.Match("true positive 5", `SONAR.LOGIN ?= "12345678ABCDEFH1234567890ABCDEFH12345678"`, "12345678ABCDEFH1234567890ABCDEFH12345678"),
		rulebuilder.Match("true positive 6", `const SONAR_TOKEN = "squ_12345678ABCDEFH1234567890ABCDEFH12345678"`, "squ_12345678ABCDEFH1234567890ABCDEFH12345678"),
		rulebuilder.Match("true positive 7", `SONAR_LOGIN := "sqp_12345678ABCDEFH1234567890ABCDEFH12345678"`, "sqp_12345678ABCDEFH1234567890ABCDEFH12345678"),
		rulebuilder.Match("true positive 8", `SONAR.TOKEN = "sqa_12345678ABCDEFH1234567890ABCDEFH12345678"`, "sqa_12345678ABCDEFH1234567890ABCDEFH12345678"),
	},
})
