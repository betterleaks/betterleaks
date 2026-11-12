package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "npm-access-token",
	Confidence:  "high",
	Description: "Uncovered an npm access token, potentially compromising package management and code repository access.",
	Regex:       rulebuilder.Token(`(?i)npm_[a-z0-9]{36}`),
	Keywords: []string{
		"npm_",
	},
	FilterExpr: `entropy(finding["secret"]) <= 2.0`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `npmAccessTokenToken = "npm_5fbbd6p84oe7ut4qrttebiwar77s63donnl8"`, "npm_5fbbd6p84oe7ut4qrttebiwar77s63donnl8"),
	},
})
