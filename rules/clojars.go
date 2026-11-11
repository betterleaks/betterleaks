package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "clojars-api-token",
	Confidence:  "high",
	Description: "Uncovered a possible Clojars API token, risking unauthorized access to Clojure libraries and potential code manipulation.",
	Regex:       `(?i)CLOJARS_[a-z0-9]{60}`,
	Keywords:    []string{"clojars_"},
	FilterExpr:  `entropy(finding["secret"]) <= 2.0`,
	Tests: []config.RuleTest{
		Match("clojars assignment", `clojarsToken = "CLOJARS_5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7n"`, "CLOJARS_5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7n"),
	},
})
