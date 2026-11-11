package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "flutterwave-public-key",
	Confidence:  "high",
	Description: "Detected a Flutterwave Public Key, potentially exposing public cryptographic operations and integrations.",
	Regex:       `FLWPUBK_TEST-(?i)[a-h0-9]{32}-X`,
	Keywords:    []string{"FLWPUBK_TEST"},
	FilterExpr:  `entropy(finding["secret"]) <= 2.0`,
	Tests: []config.RuleTest{
		Match("flutterwavePubKey assignment", `flutterwavePubKeyToken = "FLWPUBK_TEST-1f7b169c846f218ab552fa82fbf86758-X"`, "FLWPUBK_TEST-1f7b169c846f218ab552fa82fbf86758-X"),
	},
})

var _ = Add(config.Rule{
	ID:          "flutterwave-secret-key",
	Confidence:  "high",
	Description: "Identified a Flutterwave Secret Key, risking unauthorized financial transactions and data breaches.",
	Regex:       `FLWSECK_TEST-(?i)[a-h0-9]{32}-X`,
	Keywords:    []string{"FLWSECK_TEST"},
	FilterExpr:  `entropy(finding["secret"]) <= 2.0`,
	Tests: []config.RuleTest{
		Match("flutterwavePubKey assignment", `flutterwavePubKeyToken = "FLWSECK_TEST-1f7b169c846f218ab552fa82fbf86758-X"`, "FLWSECK_TEST-1f7b169c846f218ab552fa82fbf86758-X"),
	},
})

var _ = Add(config.Rule{
	ID:          "flutterwave-encryption-key",
	Confidence:  "high",
	Description: "Uncovered a Flutterwave Encryption Key, which may compromise payment processing and sensitive financial information.",
	Regex:       `FLWSECK_TEST-(?i)[a-h0-9]{12}`,
	Keywords:    []string{"FLWSECK_TEST"},
	FilterExpr:  `entropy(finding["secret"]) <= 2.0`,
	Tests: []config.RuleTest{
		Match("flutterwavePubKey assignment", `flutterwavePubKeyToken = "FLWSECK_TEST-1f7b169c846f"`, "FLWSECK_TEST-1f7b169c846f"),
	},
})
