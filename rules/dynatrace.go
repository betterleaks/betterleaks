package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "dynatrace-api-token",
	Confidence:  "high",
	Description: "Detected a Dynatrace API token, potentially risking application performance monitoring and data exposure.",
	Regex:       `dt0c01\.(?i)[a-z0-9]{24}\.[a-z0-9]{64}`,
	Keywords:    []string{"dt0c01."},
	FilterExpr:  `entropy(finding["secret"]) <= 4.0`,
	Tests: []config.RuleTest{
		Match("dynatrace assignment", `dynatraceToken = "dt0c01.5fbbd6p84oe7ut4qrttebiwa.5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7nz6lc"`, "dt0c01.5fbbd6p84oe7ut4qrttebiwa.5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7nz6lc"),
	},
})
