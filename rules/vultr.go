package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "vultr-api-key.1",
	Confidence:  "medium",
	Description: "Vultr API key, which may allow management of cloud account resources.",
	Regex:       Assignment([]string{"vultr"}, `(?i)`+Hex("36")),
	Keywords:    []string{"vultr"},
	ValidateExpr: `let r = http.get("https://api.vultr.com/v2/account", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 && (r.body contains "\"account\"") ? {
    "result": "valid"
  } : r.status == 401 && (r.body contains "Invalid API token") ? {
    "result": "invalid",
    "reason": "Invalid API token"
  } : validate.unknown(r)`,
	FilterExpr: MinEntropy(3.4),
	Tests: []config.RuleTest{
		Match("true positive 1", "VULTR_API_KEY=1f7b169c846f218ab552fa82fbf86758bf5c", "1f7b169c846f218ab552fa82fbf86758bf5c"),
		Match("true positive 2", `vultr token: "1f7b169c846f218ab552fa82fbf86758bf5c"`, "1f7b169c846f218ab552fa82fbf86758bf5c"),
		NoMatch("false positive 1", "API_KEY=1f7b169c846f218ab552fa82fbf86758bf5c"),
		NoMatch("false positive 2", "VULTR_API_KEY=short"),
		NoMatch("false positive 3", "VULTR_API_KEY=000000000000000000000000000000000000"),
	},
})
