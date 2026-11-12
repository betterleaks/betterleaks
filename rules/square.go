package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "square-access-token",
	Confidence:  "high",
	Description: "Detected a Square Access Token, risking unauthorized payment processing and financial transaction exposure.",
	Regex:       rulebuilder.Token(`(?:EAAA|sq0atp-)[\w-]{22,60}`),
	Keywords:    []string{"sq0atp-", "eaaa"},
	FilterExpr:  `entropy(finding["secret"]) <= 2.0`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `squareToken = "sq0atp-E6v05tg7Z5jXlNPAK_XEPc"`, "sq0atp-E6v05tg7Z5jXlNPAK_XEPc"),
		rulebuilder.Match("true positive 1", "ARG token=sq0atp-812erere3wewew45678901", "sq0atp-812erere3wewew45678901"),
		rulebuilder.Match("true positive 2", "ARG token=EAAAlsBxkkVgvmr7FasTFbM6VUGZ31EJ4jZKTJZySgElBDJ_wyafHuBFquFexY7E", "EAAAlsBxkkVgvmr7FasTFbM6VUGZ31EJ4jZKTJZySgElBDJ_wyafHuBFquFexY7E"),
		rulebuilder.NoMatch("false positive 1", "aws-cli@sha256:eaaa7b11777babe28e6133a8b19ff71cea687e0d7f05158dee95a71f76ce3d00"),
	},
})

// SquareSecret has never been registered in the default config.
func SquareSecret() config.Rule {
	return config.Rule{
		ID:          "square-secret",
		Confidence:  "high",
		Description: "Square Secret",
		Regex:       rulebuilder.Token(`sq0csp-[\w-]{43}`),
		Keywords:    []string{"sq0csp-"},
		FilterExpr:  `entropy(finding["secret"]) <= 2.0`,
		Tests: []config.RuleTest{
			rulebuilder.Match("true positive 1", `value: "sq0csp-0p9h7g6f4s3s3s3-4a3ardgwa6ADRDJDDKUFYDYDYDY"`, "sq0csp-0p9h7g6f4s3s3s3-4a3ardgwa6ADRDJDDKUFYDYDYDY"),
		},
	}
}
