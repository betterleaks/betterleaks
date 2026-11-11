package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "coveralls-personal-api-token",
	Confidence:  "medium",
	Description: "Detected a Coveralls personal API token, which may expose repository coverage data.",
	Regex:       Assignment([]string{"coveralls"}, `(?i)[A-Za-z0-9-]{37}`),
	Keywords:    []string{"coveralls"},
	FilterExpr:  `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("true positive 1", "coveralls_SECRETTOKEN=a1b2c3d4e5f6g7h8i9j0k1l2m3n4p5q6r7s8t", "a1b2c3d4e5f6g7h8i9j0k1l2m3n4p5q6r7s8t"),
		Match("true positive 2", "coveralls-SECRET-KEY=m1n2p3q4r5s6t7u8v9w0x1y2z3a4b5c6d7e8f", "m1n2p3q4r5s6t7u8v9w0x1y2z3a4b5c6d7e8f"),
		Match("true positive 3", "coveralls_PRIVATEKEY=1234567890bcdefghijklmnpqrstuvwxyza12", "1234567890bcdefghijklmnpqrstuvwxyza12"),
	},
})
