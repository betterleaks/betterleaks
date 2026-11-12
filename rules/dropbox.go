package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	Description: "Identified a Dropbox API secret, which could lead to unauthorized file access and data breaches in Dropbox storage.",
	ID:          "dropbox-api-token",
	Confidence:  "medium",
	Regex:       rulebuilder.Assignment([]string{"dropbox"}, `(?i)[a-z0-9]{15}`),
	FilterExpr:  rulebuilder.MinEntropyAndTokenEfficiency,
	Keywords:    []string{"dropbox"},
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `dropboxToken = "5fbbd6p84oe7ut4"`, "5fbbd6p84oe7ut4"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "dropbox-short-lived-api-token",
	Confidence:  "high",
	Description: "Discovered a Dropbox short-lived API token, posing a risk of temporary but potentially harmful data access and manipulation.",
	Regex:       rulebuilder.Assignment([]string{"dropbox"}, `(?i)sl\.[a-z0-9\-=_]{135}`),
	Keywords:    []string{"dropbox"},
	FilterExpr:  `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests:       []config.RuleTest{},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "dropbox-long-lived-api-token",
	Confidence:  "high",
	Description: "Found a Dropbox long-lived API token, risking prolonged unauthorized access to cloud storage and sensitive data.",
	Regex:       rulebuilder.Assignment([]string{"dropbox"}, `(?i)[a-z0-9]{11}(AAAAAAAAAA)[a-z0-9\-_=]{43}`),
	Keywords:    []string{"dropbox"},
	FilterExpr:  `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests:       []config.RuleTest{},
})
