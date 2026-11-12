package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "zendesk-secret-key",
	Confidence:  "high",
	Description: "Detected a Zendesk Secret Key, risking unauthorized access to customer support services and sensitive ticketing data.",
	Regex:       rulebuilder.Assignment([]string{"zendesk"}, `(?i)[a-z0-9]{40}`),
	Keywords: []string{
		"zendesk",
	},
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `zendeskToken = "5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7li"`, "5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7li"),
	},
})
