package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	Description: "Identified a Twitter API Key, which may compromise Twitter application integrations and user data security.",
	ID:          "twitter-api-key",
	Confidence:  "high",
	Regex:       rulebuilder.Assignment([]string{"twitter"}, `(?i)`+rulebuilder.AlphaNumeric("25")),
	Keywords:    []string{"twitter"},
	FilterExpr:  `entropy(finding["secret"]) < 3.0 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `twitterToken = "5fbbd6p84oe7ut4qrttebiwar"`, "5fbbd6p84oe7ut4qrttebiwar"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	Description: "Found a Twitter API Secret, risking the security of Twitter app integrations and sensitive data access.",
	ID:          "twitter-api-secret",
	Confidence:  "high",
	Regex:       rulebuilder.Assignment([]string{"twitter"}, `(?i)`+rulebuilder.AlphaNumeric("50")),
	Keywords:    []string{"twitter"},
	FilterExpr:  `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `twitterToken = "5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl"`, "5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	Description: "Discovered a Twitter Bearer Token, potentially compromising API access and data retrieval from Twitter.",
	ID:          "twitter-bearer-token",
	Confidence:  "high",
	Regex:       rulebuilder.Assignment([]string{"twitter"}, "(?i)A{22}[a-zA-Z0-9%]{80,100}"),
	Keywords:    []string{"twitter"},
	FilterExpr:  `entropy(finding["secret"]) < 3.0 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `twitterToken = "AAAAAAAAAAAAAAAAAAAAAAeoStCxpP3EVXcbLq%Jt4b8wsZpgsxTmNeV2zf6BHXUs%sZgjscQ6rfLOh2yePfu2IqY7410%7MNHRmXP"`, "AAAAAAAAAAAAAAAAAAAAAAeoStCxpP3EVXcbLq%Jt4b8wsZpgsxTmNeV2zf6BHXUs%sZgjscQ6rfLOh2yePfu2IqY7410%7MNHRmXP"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	Description: "Detected a Twitter Access Token, posing a risk of unauthorized account operations and social media data exposure.",
	ID:          "twitter-access-token",
	Confidence:  "high",
	Regex:       rulebuilder.Assignment([]string{"twitter"}, "(?i)[0-9]{15,25}-[a-zA-Z0-9]{20,40}"),
	Keywords:    []string{"twitter"},
	FilterExpr:  `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `twitterToken = "177918506041298-Gd5Xav0yu99ZAMPTA7z7"`, "177918506041298-Gd5Xav0yu99ZAMPTA7z7"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	Description: "Uncovered a Twitter Access Secret, potentially risking unauthorized Twitter integrations and data breaches.",
	ID:          "twitter-access-secret",
	Confidence:  "high",
	Regex:       rulebuilder.Assignment([]string{"twitter"}, `(?i)`+rulebuilder.AlphaNumeric("45")),
	Keywords:    []string{"twitter"},
	FilterExpr:  `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `twitterToken = "5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1"`, "5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1"),
	},
})
