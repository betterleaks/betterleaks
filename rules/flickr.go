package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "flickr-access-token",
	Confidence:  "high",
	Description: "Discovered a Flickr Access Token, posing a risk of unauthorized photo management and potential data leakage.",
	Regex:       Assignment([]string{"flickr"}, `(?i)`+AlphaNumeric("32")),

	Keywords: []string{
		"flickr",
	},
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("flickr assignment", `flickrToken = "5fbbd6p84oe7ut4qrttebiwar77s63do"`, "5fbbd6p84oe7ut4qrttebiwar77s63do"),
	},
})
