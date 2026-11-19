package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	Description: "Found a HubSpot API Token, posing a risk to CRM data integrity and unauthorized marketing operations.",
	ID:          "hubspot-api-key",
	Confidence:  "high",
	Regex: rulebuilder.Assignment(
		[]string{"hubspot"},
		`(?i)[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`,
	),
	Keywords: []string{"hubspot"},
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `hubspotToken = "1f7b169c-846f-218a-b552-fa82fbf86758"`, "1f7b169c-846f-218a-b552-fa82fbf86758"),
		rulebuilder.Match("true positive 1", `const hubspotKey = "12345678-ABCD-ABCD-ABCD-1234567890AB"`, "12345678-ABCD-ABCD-ABCD-1234567890AB"),
	},
})
