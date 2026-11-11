package rules

import "github.com/betterleaks/betterleaks/v2/config"

// https://hunter.io/api-documentation/v2#account
const hunterValidateExpr = `let r = http.get("https://api.hunter.io/v2/account", {
  "X-API-KEY": finding["secret"],
  "Accept": "application/json"
});
r.status == 200 && type(r.json) == "map" && type(r.json?.data) == "map" && (r.json?.data?.email ?? "") != "" ? {
  "result": "valid",
  "analysis": {
    "identity": {
      "email": string(r.json?.data?.email ?? ""),
      "name": trim((r.json?.data?.first_name ?? "") + " " + (r.json?.data?.last_name ?? ""))
    },
  }
} : r.status == 401 ? {
  "result": "invalid", "reason": "Unauthorized"
} : validate.unknown(r)`

const hunterAnalyzeExpr = identityOnlyAnalyzeExpr

var _ = Add(config.Rule{
	ID:           "hunter-api-key.1",
	Confidence:   "medium",
	Description:  "Hunter API key, which may allow access to account and email intelligence data.",
	Regex:        Assignment([]string{"hunter"}, Hex("40")),
	Keywords:     []string{"hunter"},
	ValidateExpr: hunterValidateExpr,
	AnalyzeExpr:  hunterAnalyzeExpr,
	FilterExpr:   MinEntropy(3.5),
	Tests: []config.RuleTest{
		Match("true positive 1", "HUNTER_API_KEY=1f7b169c846f218ab552fa82fbf86758bf5c97d2", "1f7b169c846f218ab552fa82fbf86758bf5c97d2"),
		Match("true positive 2", `hunter key: "1f7b169c846f218ab552fa82fbf86758bf5c97d2"`, "1f7b169c846f218ab552fa82fbf86758bf5c97d2"),
		NoMatch("false positive 1", "API_KEY=1f7b169c846f218ab552fa82fbf86758bf5c97d2"),
		NoMatch("false positive 2", "HUNTER_API_KEY=test-api-key"),
		NoMatch("false positive 3", "HUNTER_API_KEY=0000000000000000000000000000000000000000"),
	},
})
