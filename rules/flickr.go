package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "flickr-access-token",
	Confidence:  "high",
	Description: "Discovered a Flickr Access Token, posing a risk of unauthorized photo management and potential data leakage.",
	Regex:       rulebuilder.Assignment([]string{"flickr"}, `(?i)[a-z0-9]{32}`),
	Keywords: []string{
		"flickr",
	},
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `flickrToken = "5fbbd6p84oe7ut4qrttebiwar77s63do"`, "5fbbd6p84oe7ut4qrttebiwar77s63do"),
	},
})
