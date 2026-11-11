package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	// Human redable description of the rule
	Description: "Identified a Defined Networking API token, which could lead to unauthorized network operations and data breaches.",

	// Unique ID for the rule
	ID:         "defined-networking-api-token",
	Confidence: "high",

	// Regex used for detecting secrets. See regex section below for more details
	Regex: Assignment([]string{"dnkey"}, `(?i)dnkey-[a-z0-9=_\-]{26}-[a-z0-9=_\-]{52}`),

	// Keywords used for string matching on fragments (think of this as a prefilter)
	Keywords: []string{"dnkey"},
	Tests: []config.RuleTest{
		Match("dnkey assignment", `dnkeyToken = "dnkey-ki=bm50nvcz3-wjwuth1tchax6-ki=bm50nvcz3-wjwuth1tchax6992fd-41l48soc903fsrsj9cld"`, "dnkey-ki=bm50nvcz3-wjwuth1tchax6-ki=bm50nvcz3-wjwuth1tchax6992fd-41l48soc903fsrsj9cld"),
	},
})
