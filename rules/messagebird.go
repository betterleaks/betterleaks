package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	Description: "Found a MessageBird API token, risking unauthorized access to communication platforms and message data.",
	ID:          "messagebird-api-token",
	Confidence:  "high",
	Regex:       Assignment([]string{"message[_-]?bird"}, `(?i)`+AlphaNumeric("25")),

	Keywords: []string{
		"messagebird",
		"message-bird",
		"message_bird",
	},
	FilterExpr: `entropy(finding["secret"]) < 3.0 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("messagebird assignment", `messagebirdToken = "5fbbd6p84oe7ut4qrttebiwar"`, "5fbbd6p84oe7ut4qrttebiwar"),
		Match("message-bird assignment", `message-birdToken = "5fbbd6p84oe7ut4qrttebiwar"`, "5fbbd6p84oe7ut4qrttebiwar"),
		Match("message_bird assignment", `message_birdToken = "5fbbd6p84oe7ut4qrttebiwar"`, "5fbbd6p84oe7ut4qrttebiwar"),
	},
})

var _ = Add(config.Rule{
	Description: "Discovered a MessageBird client ID, potentially compromising API integrations and sensitive communication data.",
	ID:          "messagebird-client-id",
	Confidence:  "high",
	Regex:       Assignment([]string{"message[_-]?bird"}, `(?i)`+Hex8_4_4_4_12()),

	Keywords: []string{
		"messagebird",
		"message-bird",
		"message_bird",
	},
	FilterExpr: `entropy(finding["secret"]) < 3.3 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("MessageBird assignment", `MessageBirdToken = "12345678-ABCD-ABCD-ABCD-1234567890AB"`, "12345678-ABCD-ABCD-ABCD-1234567890AB"),
		Match("true positive 1", `const MessageBirdClientID = "12345678-ABCD-ABCD-ABCD-1234567890AB"`, "12345678-ABCD-ABCD-ABCD-1234567890AB"),
	},
})
