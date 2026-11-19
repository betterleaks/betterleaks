package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "duffel-api-token",
	Confidence:  "high",
	Description: "Uncovered a Duffel API token, which may compromise travel platform integrations and sensitive customer data.",
	Regex:       `duffel_(?:test|live)_(?i)[a-z0-9_\-=]{43}`,
	Keywords:    []string{"duffel_"},
	FilterExpr:  `entropy(finding["secret"]) <= 2.0`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `duffelToken = "duffel_test_ki=bm50nvcz3-wjwuth1tchax6992fd-41l48soc903"`, "duffel_test_ki=bm50nvcz3-wjwuth1tchax6992fd-41l48soc903"),
	},
})
