package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "adobe-client-id",
	Confidence:  "high",
	Description: "Detected a pattern that resembles an Adobe OAuth Web Client ID, posing a risk of compromised Adobe integrations and data breaches.",
	Regex:       Assignment([]string{"adobe"}, `(?i)`+Hex("32")),
	Keywords:    []string{"adobe"},
	FilterExpr:  `entropy(finding["secret"]) < 3.0 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("adobe assignment", `adobeToken = "1f7b169c846f218ab552fa82fbf86758"`, "1f7b169c846f218ab552fa82fbf86758"),
	},
})

var _ = Add(config.Rule{
	ID:          "adobe-client-secret",
	Confidence:  "high",
	Description: "Discovered a potential Adobe Client Secret, which, if exposed, could allow unauthorized Adobe service access and data manipulation.",
	Regex:       Token(`p8e-(?i)[a-z0-9]{32}`),
	Keywords:    []string{"p8e-"},
	FilterExpr:  `entropy(finding["secret"]) < 3.0`,
	Tests: []config.RuleTest{
		Match("true positive 1", `adobeClient := "p8e-1f7b169c846f218ab552fa82fbf86758"`, "p8e-1f7b169c846f218ab552fa82fbf86758"),
	},
})
