package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	Description: "Found a HubSpot API Token, posing a risk to CRM data integrity and unauthorized marketing operations.",
	ID:          "hubspot-api-key",
	Confidence:  "high",
	Regex: Assignment([]string{"hubspot"},
		`(?i)[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`),

	Keywords: []string{"hubspot"},
	Tests: []config.RuleTest{
		Match("hubspot assignment", `hubspotToken = "1f7b169c-846f-218a-b552-fa82fbf86758"`, "1f7b169c-846f-218a-b552-fa82fbf86758"),
		Match("true positive 1", `const hubspotKey = "12345678-ABCD-ABCD-ABCD-1234567890AB"`, "12345678-ABCD-ABCD-ABCD-1234567890AB"),
	},
})
