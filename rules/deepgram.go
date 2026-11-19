package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "deepgram-api-key",
	Confidence:  "high",
	Description: "Detected a Deepgram API Key, which may expose speech recognition services and audio data to unauthorized access.",
	Regex:       rulebuilder.Assignment([]string{"deepgram"}, `(?i)[a-f0-9]{40}`),
	Keywords:    []string{"deepgram"},
	FilterExpr:  `entropy(finding["secret"]) < 3.3 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `deepgramToken = "1f7b169c846f218ab552fa82fbf86758bf5c97d2"`, "1f7b169c846f218ab552fa82fbf86758bf5c97d2"),
		rulebuilder.NoMatch("Too short", "deepgram_key = 948c19ecde2818a1a357fffb14d2fc2a"),
		rulebuilder.NoMatch("All zeros (low entropy)", "deepgram_key = 0000000000000000000000000000000000000000"),
	},
})
