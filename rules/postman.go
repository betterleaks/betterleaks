package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "postman-api-token",
	Confidence:  "high",
	Description: "Uncovered a Postman API token, potentially compromising API testing and development workflows.",
	Regex:       Token(`PMAK-(?i)[a-f0-9]{24}\-[a-f0-9]{34}`),
	Keywords: []string{
		"PMAK-",
	},
	FilterExpr: `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		Match("postmanAPItoken assignment", `postmanAPItokenToken = "PMAK-1f7b169c846f218ab552fa82-1f7b169c846f218ab552fa82fbf86758bf"`, "PMAK-1f7b169c846f218ab552fa82-1f7b169c846f218ab552fa82fbf86758bf"),
	},
})
