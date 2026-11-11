package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "readme-api-token",
	Confidence:  "high",
	Description: "Detected a Readme API token, risking unauthorized documentation management and content exposure.",
	Regex:       Token(`rdme_[a-z0-9]{70}`),
	Keywords: []string{
		"rdme_",
	},
	FilterExpr: `entropy(finding["secret"]) <= 2.0`,
	Tests: []config.RuleTest{
		Match("api-token assignment", `api-tokenToken = "rdme_5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7nz6lca8hqn2"`, "rdme_5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7nz6lca8hqn2"),
		NoMatch("false positive 1", "const API_KEY = 'rdme_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX';"),
	},
})
