package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	Description: "Discovered a Contentful delivery API token, posing a risk to content management systems and data integrity.",
	ID:          "contentful-delivery-api-token",
	Confidence:  "medium",
	Regex:       rulebuilder.Assignment([]string{"contentful"}, `(?i)[a-z0-9=_\-]{43}`),
	Keywords:    []string{"contentful"},
	FilterExpr:  `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `contentfulToken = "5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipma"`, "5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipma"),
	},
})
