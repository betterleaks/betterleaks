package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "postman-api-token",
	Confidence:  "high",
	Description: "Uncovered a Postman API token, potentially compromising API testing and development workflows.",
	Regex:       rulebuilder.Token(`PMAK-(?i)[a-f0-9]{24}\-[a-f0-9]{34}`),
	Keywords: []string{
		"pmak-",
	},
	FilterExpr: `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `postmanAPItokenToken = "PMAK-1f7b169c846f218ab552fa82-1f7b169c846f218ab552fa82fbf86758bf"`, "PMAK-1f7b169c846f218ab552fa82-1f7b169c846f218ab552fa82fbf86758bf"),
	},
})
