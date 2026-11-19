package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	Description: "Uncovered a Lob API Key, which could lead to unauthorized access to mailing and address verification services.",
	ID:          "lob-api-key",
	Confidence:  "medium",
	Regex:       rulebuilder.Assignment([]string{"lob"}, `(?i)(live|test)_[a-f0-9]{35}`),
	Keywords: []string{
		"test_",
		"live_",
	},
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `lobToken = "test_1f7b169c846f218ab552fa82fbf86758bf5"`, "test_1f7b169c846f218ab552fa82fbf86758bf5"),
	},
})
