package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "discord-api-token",
	Confidence:  "medium",
	Description: "Detected a Discord API key, potentially compromising communication channels and user data privacy on Discord.",
	Regex:       Assignment([]string{"discord"}, `(?i)`+Hex("64")),
	Keywords:    []string{"discord"},
	FilterExpr:  `entropy(finding["secret"]) < 3.3 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("discord assignment", `discordToken = "1f7b169c846f218ab552fa82fbf86758bf5c97d2d2a313e4f95957818a7b3edc"`, "1f7b169c846f218ab552fa82fbf86758bf5c97d2d2a313e4f95957818a7b3edc"),
	},
})

var _ = Add(config.Rule{
	ID:          "discord-client-id",
	Confidence:  "medium",
	Description: "Identified a Discord client ID, which may lead to unauthorized integrations and data exposure in Discord applications.",
	Regex:       Assignment([]string{"discord"}, `(?i)`+Numeric("18")),
	Keywords:    []string{"discord"},
	FilterExpr:  `entropy(finding["secret"]) < 2.75`,
	Tests: []config.RuleTest{
		Match("discord assignment", `discordToken = "177918506041298415"`, "177918506041298415"),
		NoMatch("Low entropy", "discord=000000000000000000"),
	},
})

var _ = Add(config.Rule{
	ID:          "discord-client-secret",
	Confidence:  "medium",
	Description: "Discovered a potential Discord client secret, risking compromised Discord bot integrations and data leaks.",
	Regex:       Assignment([]string{"discord"}, `(?i)`+AlphaNumericExtended("32")),
	Keywords:    []string{"discord"},
	FilterExpr:  `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("discord assignment", `discordToken = "ki=bm50nvcz3-wjwuth1tchax6992fd-"`, "ki=bm50nvcz3-wjwuth1tchax6992fd-"),
		NoMatch("Low entropy", "discord=00000000000000000000000000000000"),
	},
})
