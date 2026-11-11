package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "digitalocean-pat",
	Confidence:  "high",
	Description: "Discovered a DigitalOcean Personal Access Token, posing a threat to cloud infrastructure security and data privacy.",
	Regex:       Token(`dop_v1_[a-f0-9]{64}`),
	Keywords:    []string{"dop_v1_"},
	FilterExpr:  `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		Match("do assignment", `doToken = "dop_v1_1f7b169c846f218ab552fa82fbf86758bf5c97d2d2a313e4f95957818a7b3edc"`, "dop_v1_1f7b169c846f218ab552fa82fbf86758bf5c97d2d2a313e4f95957818a7b3edc"),
	},
})

var _ = Add(config.Rule{
	ID:          "digitalocean-access-token",
	Confidence:  "high",
	Description: "Found a DigitalOcean OAuth Access Token, risking unauthorized cloud resource access and data compromise.",
	Regex:       Token(`doo_v1_[a-f0-9]{64}`),
	Keywords:    []string{"doo_v1_"},
	FilterExpr:  `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		Match("do assignment", `doToken = "doo_v1_1f7b169c846f218ab552fa82fbf86758bf5c97d2d2a313e4f95957818a7b3edc"`, "doo_v1_1f7b169c846f218ab552fa82fbf86758bf5c97d2d2a313e4f95957818a7b3edc"),
	},
})

var _ = Add(config.Rule{
	Description: "Uncovered a DigitalOcean OAuth Refresh Token, which could allow prolonged unauthorized access and resource manipulation.",
	ID:          "digitalocean-refresh-token",
	Confidence:  "high",

	Regex:    Token(`(?i)dor_v1_[a-f0-9]{64}`),
	Keywords: []string{"dor_v1_"},
	Tests: []config.RuleTest{
		Match("do assignment", `doToken = "dor_v1_1f7b169c846f218ab552fa82fbf86758bf5c97d2d2a313e4f95957818a7b3edc"`, "dor_v1_1f7b169c846f218ab552fa82fbf86758bf5c97d2d2a313e4f95957818a7b3edc"),
	},
})
