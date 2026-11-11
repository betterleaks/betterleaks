package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "kraken-access-token",
	Confidence:  "medium",
	Description: "Identified a Kraken Access Token, potentially compromising cryptocurrency trading accounts and financial security.",
	Regex: Assignment([]string{"kraken"},
		`(?i)`+AlphaNumericExtendedLong("80,90")),

	Keywords: []string{
		"kraken",
	},
	FilterExpr: `entropy(finding["secret"]) < 4.0 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("kraken assignment", `krakenToken = "wrte4fspg1n/1+o3ned81p0j9g+_bikz102/gqjcar1ovuik4sdzjvqx8cqhn2kn68qc1v+x9+wf6=kj"`, "wrte4fspg1n/1+o3ned81p0j9g+_bikz102/gqjcar1ovuik4sdzjvqx8cqhn2kn68qc1v+x9+wf6=kj"),
	},
})
