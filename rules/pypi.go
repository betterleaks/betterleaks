package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	Description: "Discovered a PyPI upload token, potentially compromising Python package distribution and repository integrity.",
	ID:          "pypi-upload-token",
	Confidence:  "high",
	Regex:       `pypi-AgEIcHlwaS5vcmc[\w-]{50,1000}`,
	Keywords: []string{
		"pypi-AgEIcHlwaS5vcmc",
	},
	FilterExpr: `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		Match("pypi assignment", `pypiToken = "pypi-AgEIcHlwaS5vcmc1f7b169c846f218ab552fa82fbf867581f7b169c846f218ab552fa82fbf86758"`, "pypi-AgEIcHlwaS5vcmc1f7b169c846f218ab552fa82fbf867581f7b169c846f218ab552fa82fbf86758"),
	},
})
