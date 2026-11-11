package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "doppler-api-token",
	Confidence:  "high",
	Description: "Discovered a Doppler API token, posing a risk to environment and secrets management security.",
	Regex:       `dp\.pt\.(?i)[a-z0-9]{43}`,
	Keywords:    []string{`dp.pt.`},
	FilterExpr:  `entropy(finding["secret"]) <= 2.0`,
	Tests: []config.RuleTest{
		Match("doppler assignment", `dopplerToken = "dp.pt.5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipma"`, "dp.pt.5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipma"),
	},
})

// TODO add additional doppler formats:
// https://docs.doppler.com/reference/auth-token-formats
