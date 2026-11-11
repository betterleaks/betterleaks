package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "zendesk-secret-key",
	Confidence:  "high",
	Description: "Detected a Zendesk Secret Key, risking unauthorized access to customer support services and sensitive ticketing data.",
	Regex:       Assignment([]string{"zendesk"}, `(?i)`+AlphaNumeric("40")),
	Keywords: []string{
		"zendesk",
	},
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("zendesk assignment", `zendeskToken = "5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7li"`, "5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7li"),
	},
})
