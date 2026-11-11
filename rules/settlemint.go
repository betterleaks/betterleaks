package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	Description: "Found a Settlemint Personal Access Token.",
	ID:          "settlemint-personal-access-token",
	Confidence:  "high",
	Regex:       Token(`sm_pat_[a-zA-Z0-9]{16}`),
	Keywords: []string{
		"sm_pat",
	},
	FilterExpr: `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		Match("settlemintToken assignment", `settlemintTokenToken = "sm_pat_5fbbd6p84oe7ut4q"`, "sm_pat_5fbbd6p84oe7ut4q"),
		NoMatch("false positive 1", `nonMatchingToken := "5fbbd6p84oe7ut4q"`),
		NoMatch("false positive 2", `nonMatchingToken := "sm_pat_5fbbd6p84o"`),
	},
})

var _ = Add(config.Rule{
	Description: "Found a Settlemint Application Access Token.",
	ID:          "settlemint-application-access-token",
	Confidence:  "high",
	Regex:       Token(`sm_aat_[a-zA-Z0-9]{16}`),
	Keywords: []string{
		"sm_aat",
	},
	FilterExpr: `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		Match("settlemintToken assignment", `settlemintTokenToken = "sm_aat_5fbbd6p84oe7ut4q"`, "sm_aat_5fbbd6p84oe7ut4q"),
		NoMatch("false positive 1", `nonMatchingToken := "5fbbd6p84oe7ut4q"`),
		NoMatch("false positive 2", `nonMatchingToken := "sm_aat_5fbbd6p84o"`),
	},
})

var _ = Add(config.Rule{
	Description: "Found a Settlemint Service Access Token.",
	ID:          "settlemint-service-access-token",
	Confidence:  "high",
	Regex:       Token(`sm_sat_[a-zA-Z0-9]{16}`),
	Keywords: []string{
		"sm_sat",
	},
	FilterExpr: `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		Match("settlemintToken assignment", `settlemintTokenToken = "sm_sat_5fbbd6p84oe7ut4q"`, "sm_sat_5fbbd6p84oe7ut4q"),
		NoMatch("false positive 1", `nonMatchingToken := "5fbbd6p84oe7ut4q"`),
		NoMatch("false positive 2", `nonMatchingToken := "sm_sat_5fbbd6p84o"`),
	},
})
