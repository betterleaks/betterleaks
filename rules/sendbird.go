package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "sendbird-access-token",
	Confidence:  "high",
	Description: "Uncovered a Sendbird Access Token, potentially risking unauthorized access to communication services and user data.",
	Regex:       Assignment([]string{"sendbird"}, `(?i)`+Hex("40")),

	Keywords: []string{
		"sendbird",
	},
	FilterExpr: `entropy(finding["secret"]) < 3.3 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("sendbird assignment", `sendbirdToken = "1f7b169c846f218ab552fa82fbf86758bf5c97d2"`, "1f7b169c846f218ab552fa82fbf86758bf5c97d2"),
	},
})

var _ = Add(config.Rule{
	ID:          "sendbird-access-id",
	Confidence:  "high",
	Description: "Discovered a Sendbird Access ID, which could compromise chat and messaging platform integrations.",
	Regex:       Assignment([]string{"sendbird"}, `(?i)`+Hex8_4_4_4_12()),

	Keywords: []string{
		"sendbird",
	},
	FilterExpr: `entropy(finding["secret"]) < 3.3 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("sendbird assignment", `sendbirdToken = "1f7b169c-846f-218a-b552-fa82fbf86758"`, "1f7b169c-846f-218a-b552-fa82fbf86758"),
	},
})
