package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "mattermost-access-token",
	Confidence:  "medium",
	Description: "Identified a Mattermost Access Token, which may compromise team communication channels and data privacy.",
	Regex:       rulebuilder.Assignment([]string{"mattermost"}, `(?i)`+rulebuilder.AlphaNumeric("26")),
	Keywords: []string{
		"mattermost",
	},
	FilterExpr: `entropy(finding["secret"]) < 3.0 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `mattermostToken = "5fbbd6p84oe7ut4qrttebiwar7"`, "5fbbd6p84oe7ut4qrttebiwar7"),
	},
})
