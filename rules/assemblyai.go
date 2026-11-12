package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "assemblyai-api-key",
	Confidence:  "medium",
	Description: "Detected an AssemblyAI API Key, which may expose speech-to-text services and associated audio data to unauthorized access.",
	Regex:       rulebuilder.Assignment([]string{"assemblyai"}, `(?i)`+rulebuilder.AlphaNumeric("32")),
	Keywords:    []string{"assemblyai"},
	FilterExpr:  `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `assemblyaiToken = "5fbbd6p84oe7ut4qrttebiwar77s63do"`, "5fbbd6p84oe7ut4qrttebiwar77s63do"),
		rulebuilder.NoMatch("Too short", "assemblyai = fa0ed91518b345468f9df757"),
		rulebuilder.NoMatch("All same chars (low entropy)", "assemblyai = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
	},
})
