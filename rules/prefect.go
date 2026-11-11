package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "prefect-api-token",
	Confidence:  "high",
	Description: "Detected a Prefect API token, risking unauthorized access to workflow management and automation services.",
	Regex:       Token(`pnu_[a-zA-Z0-9]{36}`),
	Keywords: []string{
		"pnu_",
	},
	FilterExpr: `entropy(finding["secret"]) <= 2.0`,
	Tests: []config.RuleTest{
		Match("api-token assignment", `api-tokenToken = "pnu_5fbbd6p84oe7ut4qrttebiwar77s63donnl8"`, "pnu_5fbbd6p84oe7ut4qrttebiwar77s63donnl8"),
		NoMatch("false positive 1", `PREFECT_API_KEY = "pnu_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"`),
	},
})
