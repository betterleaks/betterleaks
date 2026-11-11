package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "retell-api-key.1",
	Confidence:  "high",
	Description: "Retell AI API key, which may allow access to agents, calls, and account configuration.",
	Regex:       Assignment([]string{"retell"}, `key_`+Hex("28")),
	Keywords:    []string{"retell"},
	ValidateExpr: `let r = http.get("https://api.retellai.com/get-concurrency", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 && (r.body contains "\"current_concurrency\"") && (r.body contains "\"concurrency_limit\"") ? {
    "result": "valid"
  } : r.status == 401 && (r.body contains "Invalid API Key") ? {
    "result": "invalid",
    "reason": "Invalid API key"
  } : validate.unknown(r)`,
	FilterExpr: MinEntropy(3.0),
	Tests: []config.RuleTest{
		Match("true positive 1", "RETELL_API_KEY=key_1f7b169c846f218ab552fa82fbf8", "key_1f7b169c846f218ab552fa82fbf8"),
		Match("true positive 2", `retell.ai token: "key_1f7b169c846f218ab552fa82fbf8"`, "key_1f7b169c846f218ab552fa82fbf8"),
		NoMatch("false positive 1", "API_KEY=key_1f7b169c846f218ab552fa82fbf8"),
		NoMatch("false positive 2", "RETELL_API_KEY=key_short"),
		NoMatch("false positive 3", "RETELL_API_KEY=key_0000000000000000000000000000"),
	},
})
