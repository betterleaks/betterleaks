package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "sendbird-access-token",
	Confidence:  "high",
	Description: "Uncovered a Sendbird Access Token, potentially risking unauthorized access to communication services and user data.",
	Regex:       rulebuilder.Assignment([]string{"sendbird"}, `(?i)[a-f0-9]{40}`),
	Keywords: []string{
		"sendbird",
	},
	FilterExpr: `entropy(finding["secret"]) < 3.3 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `sendbirdToken = "1f7b169c846f218ab552fa82fbf86758bf5c97d2"`, "1f7b169c846f218ab552fa82fbf86758bf5c97d2"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "sendbird-access-id",
	Confidence:  "high",
	Description: "Discovered a Sendbird Access ID, which could compromise chat and messaging platform integrations.",
	Regex:       rulebuilder.Assignment([]string{"sendbird"}, `(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
	Keywords: []string{
		"sendbird",
	},
	FilterExpr: `entropy(finding["secret"]) < 3.3 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `sendbirdToken = "1f7b169c-846f-218a-b552-fa82fbf86758"`, "1f7b169c-846f-218a-b552-fa82fbf86758"),
	},
})
