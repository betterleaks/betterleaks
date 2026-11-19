package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "netlify-access-token",
	Confidence:  "high",
	Description: "Detected a Netlify Access Token, potentially compromising web hosting services and site management.",
	Regex:       rulebuilder.Assignment([]string{"netlify"}, `(?i)[a-z0-9=_\-]{40,46}`),
	Keywords: []string{
		"netlify",
	},
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `netlifyToken = "ki=bm50nvcz3-wjwuth1tchax6992fd-41l48soc"`, "ki=bm50nvcz3-wjwuth1tchax6992fd-41l48soc"),
	},
})
