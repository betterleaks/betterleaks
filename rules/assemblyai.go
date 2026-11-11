package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "assemblyai-api-key",
	Confidence:  "medium",
	Description: "Detected an AssemblyAI API Key, which may expose speech-to-text services and associated audio data to unauthorized access.",
	Regex:       Assignment([]string{"assemblyai"}, `(?i)`+AlphaNumeric("32")),
	Keywords:    []string{"assemblyai"},
	FilterExpr:  `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("assemblyai assignment", `assemblyaiToken = "5fbbd6p84oe7ut4qrttebiwar77s63do"`, "5fbbd6p84oe7ut4qrttebiwar77s63do"),
		NoMatch("Too short", "assemblyai = fa0ed91518b345468f9df757"),
		NoMatch("All same chars (low entropy)", "assemblyai = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
	},
})
