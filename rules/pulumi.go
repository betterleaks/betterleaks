package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "pulumi-api-token",
	Confidence:  "high",
	Description: "Found a Pulumi API token, posing a risk to infrastructure as code services and cloud resource management.",
	Regex:       Token(`pul-[a-f0-9]{40}`),
	Keywords: []string{
		"pul-",
	},
	FilterExpr: `entropy(finding["secret"]) <= 2.0`,
	Tests: []config.RuleTest{
		Match("pulumi-api-token assignment", `pulumi-api-tokenToken = "pul-1f7b169c846f218ab552fa82fbf86758bf5c97d2"`, "pul-1f7b169c846f218ab552fa82fbf86758bf5c97d2"),
		NoMatch("false positive 1", `                        <img src="./assets/vipul-f0eb1acf0da84c06a50c5b2c59932001997786b176dec02bd16128ee9ea83628.png" alt="" class="w-16 h-16 rounded-full">`),
	},
})
