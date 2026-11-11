package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	Description: "Detected a Beamer API token, potentially compromising content management and exposing sensitive notifications and updates.",
	ID:          "beamer-api-token",
	Confidence:  "medium",
	Regex: Assignment([]string{"beamer"},
		`(?i)b_[a-z0-9=_\-]{44}`),
	Keywords: []string{"beamer"},
	Tests: []config.RuleTest{
		Match("assignment", `beamerToken = "b_ki=bm50nvcz3-wjwuth1tchax6992fd-41l48soc903f"`, "b_ki=bm50nvcz3-wjwuth1tchax6992fd-41l48soc903f"),
		NoMatch("firmware file name in a directory tree", "│\u00a0\u00a0 ├── R21A-A-V010SP13RC181024R16900-CN-B_250K-Release-OTA-97B6C6C59241976086FABDC41472150C.bfu"),
	},
})
