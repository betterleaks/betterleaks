package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "flutterwave-secret-key",
	Confidence:  "high",
	Description: "Identified a Flutterwave Secret Key, risking unauthorized financial transactions and data breaches.",
	Regex:       `FLWSECK_TEST-(?i)[a-h0-9]{32}-X`,
	Keywords:    []string{"flwseck_test"},
	FilterExpr:  `entropy(finding["secret"]) <= 2.0`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `flutterwavePubKeyToken = "FLWSECK_TEST-1f7b169c846f218ab552fa82fbf86758-X"`, "FLWSECK_TEST-1f7b169c846f218ab552fa82fbf86758-X"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "flutterwave-encryption-key",
	Confidence:  "high",
	Description: "Uncovered a Flutterwave Encryption Key, which may compromise payment processing and sensitive financial information.",
	Regex:       `FLWSECK_TEST-(?i)[a-h0-9]{12}`,
	Keywords:    []string{"flwseck_test"},
	FilterExpr:  `entropy(finding["secret"]) <= 2.0`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `flutterwavePubKeyToken = "FLWSECK_TEST-1f7b169c846f"`, "FLWSECK_TEST-1f7b169c846f"),
	},
})
