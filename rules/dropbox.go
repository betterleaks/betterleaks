package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	Description: "Identified a Dropbox API secret, which could lead to unauthorized file access and data breaches in Dropbox storage.",
	ID:          "dropbox-api-token",
	Confidence:  "medium",
	Regex:       Assignment([]string{"dropbox"}, `(?i)`+AlphaNumeric("15")),
	FilterExpr:  MinEntropyAndTokenEfficiency,

	Keywords: []string{"dropbox"},
	Tests: []config.RuleTest{
		Match("dropbox assignment", `dropboxToken = "5fbbd6p84oe7ut4"`, "5fbbd6p84oe7ut4"),
	},
})

var _ = Add(config.Rule{
	ID:          "dropbox-short-lived-api-token",
	Confidence:  "high",
	Description: "Discovered a Dropbox short-lived API token, posing a risk of temporary but potentially harmful data access and manipulation.",
	Regex:       Assignment([]string{"dropbox"}, `(?i)sl\.[a-z0-9\-=_]{135}`),
	Keywords:    []string{"dropbox"},
	FilterExpr:  `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests:       []config.RuleTest{},
})

var _ = Add(config.Rule{
	ID:          "dropbox-long-lived-api-token",
	Confidence:  "high",
	Description: "Found a Dropbox long-lived API token, risking prolonged unauthorized access to cloud storage and sensitive data.",
	Regex:       Assignment([]string{"dropbox"}, `(?i)[a-z0-9]{11}(AAAAAAAAAA)[a-z0-9\-_=]{43}`),
	Keywords:    []string{"dropbox"},
	FilterExpr:  `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests:       []config.RuleTest{},
})
