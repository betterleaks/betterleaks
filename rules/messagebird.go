package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	Description: "Found a MessageBird API token, risking unauthorized access to communication platforms and message data.",
	ID:          "messagebird-api-token",
	Confidence:  "high",
	Regex:       rulebuilder.Assignment([]string{"message[_-]?bird"}, `(?i)`+rulebuilder.AlphaNumeric("25")),
	Keywords: []string{
		"messagebird",
		"message-bird",
		"message_bird",
	},
	FilterExpr: `entropy(finding["secret"]) < 3.0 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("messagebird assignment", `messagebirdToken = "5fbbd6p84oe7ut4qrttebiwar"`, "5fbbd6p84oe7ut4qrttebiwar"),
		rulebuilder.Match("message-bird assignment", `message-birdToken = "5fbbd6p84oe7ut4qrttebiwar"`, "5fbbd6p84oe7ut4qrttebiwar"),
		rulebuilder.Match("message_bird assignment", `message_birdToken = "5fbbd6p84oe7ut4qrttebiwar"`, "5fbbd6p84oe7ut4qrttebiwar"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	Description: "Discovered a MessageBird client ID, potentially compromising API integrations and sensitive communication data.",
	ID:          "messagebird-client-id",
	Confidence:  "high",
	Regex:       rulebuilder.Assignment([]string{"message[_-]?bird"}, `(?i)`+rulebuilder.Hex8_4_4_4_12()),
	Keywords: []string{
		"messagebird",
		"message-bird",
		"message_bird",
	},
	FilterExpr: `entropy(finding["secret"]) < 3.3 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `MessageBirdToken = "12345678-ABCD-ABCD-ABCD-1234567890AB"`, "12345678-ABCD-ABCD-ABCD-1234567890AB"),
		rulebuilder.Match("true positive 1", `const MessageBirdClientID = "12345678-ABCD-ABCD-ABCD-1234567890AB"`, "12345678-ABCD-ABCD-ABCD-1234567890AB"),
	},
})
