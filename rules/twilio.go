package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "twilio-api-key",
	Confidence:  "high",
	Description: "Found a Twilio API Key, posing a risk to communication services and sensitive customer interaction data.",
	Regex:       `SK[0-9a-fA-F]{32}`,
	Keywords:    []string{"twilio"},
	FilterExpr:  `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		Match("twilio assignment", `twilioToken = "SK1f7b169c846f218ab552fa82fbf86758"`, "SK1f7b169c846f218ab552fa82fbf86758"),
	},
})
