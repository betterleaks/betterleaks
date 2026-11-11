package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "stability-ai-api-key",
	Confidence:  "medium",
	Description: "Detected a Stability AI API Key, which may expose AI image generation services to unauthorized access.",
	Regex:       Assignment([]string{"stability"}, `(?i)sk-[A-Za-z0-9]{48}`),
	Keywords:    []string{"stability"},
	FilterExpr:  `entropy(finding["secret"]) <= 3.5`,
	Tests: []config.RuleTest{
		Match("stability assignment", `stabilityToken = "sk-RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klKiz9pyK"`, "sk-RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klKiz9pyK"),
		NoMatch("Too short", "stability_key = sk-AnmgropvAII5XEoxVPjbnSMG3XhacEwhJlLh8"),
		NoMatch("Low entropy (all same chars)", "stability_key = sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
	},
})
