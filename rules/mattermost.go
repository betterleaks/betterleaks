package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "mattermost-access-token",
	Confidence:  "medium",
	Description: "Identified a Mattermost Access Token, which may compromise team communication channels and data privacy.",
	Regex:       Assignment([]string{"mattermost"}, `(?i)`+AlphaNumeric("26")),

	Keywords: []string{
		"mattermost",
	},
	FilterExpr: `entropy(finding["secret"]) < 3.0 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("mattermost assignment", `mattermostToken = "5fbbd6p84oe7ut4qrttebiwar7"`, "5fbbd6p84oe7ut4qrttebiwar7"),
	},
})
