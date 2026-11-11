package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "ollama-api-key",
	Confidence:  "high",
	Description: "Detected an Ollama API Key, which may expose local and hosted AI model serving to unauthorized access.",
	Regex:       Assignment([]string{"ollama"}, `(?i)[a-f0-9]{32}\.[a-zA-Z0-9_-]{24}`),
	Keywords:    []string{"ollama"},
	FilterExpr:  `entropy(finding["secret"]) <= 3.5`,
	Tests: []config.RuleTest{
		Match("ollama assignment", `ollamaToken = "bf5c97d2d2a313e4f95957818a7b3edc.WE6v05tg7Z5jXlNPAK_XEPcH"`, "bf5c97d2d2a313e4f95957818a7b3edc.WE6v05tg7Z5jXlNPAK_XEPcH"),
		NoMatch("Too short body", "ollama key = 8bcdd9b4e28e4e1b8bf14a2eb8701220"),
		NoMatch("Missing dot separator", "ollama key = 8bcdd9b4e28e4e1b8bf14a2eb8701220QH5p5TU2BDwzHu5_RCtvJXsj"),
	},
})
