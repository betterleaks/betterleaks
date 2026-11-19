package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

// https://linear.app/developers/graphql
const linearValidateExpr = `let r = http.post("https://api.linear.app/graphql", {"Authorization": finding["secret"], "Content-Type": "application/json"}, "{\"query\":\"query { viewer { id name email } }\"}");
r.status == 200 && type(r.json) == "map" && type(r.json?.data) == "map" && type(r.json?.data?.viewer) == "map" && (r.json?.data?.viewer?.id ?? "") != "" && len(r.json?.errors ?? []) == 0 ? {
  "result": "valid",
  "analysis": {
    "identity": {
      "id": string(r.json?.data?.viewer?.id ?? ""),
      "name": string(r.json?.data?.viewer?.name ?? ""),
      "email": string(r.json?.data?.viewer?.email ?? "")
    }
  }
} : r.status == 401 ? {
  "result": "invalid", "reason": "Unauthorized"
} : validate.unknown(r)`

const linearAnalyzeExpr = rulebuilder.IdentityOnlyAnalyzeExpr

var _ = rulebuilder.Add(config.Rule{
	ID:           "linear-api-key",
	Confidence:   "high",
	Description:  "Detected a Linear API Token, posing a risk to project management tools and sensitive task data.",
	Regex:        `lin_api_(?i)[a-z0-9]{40}`,
	Keywords:     []string{"lin_api_"},
	ValidateExpr: linearValidateExpr,
	AnalyzeExpr:  linearAnalyzeExpr,
	FilterExpr:   `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `linearToken = "lin_api_5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7li"`, "lin_api_5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7li"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "linear-client-secret",
	Confidence:  "medium",
	Description: "Identified a Linear Client Secret, which may compromise secure integrations and sensitive project management data.",
	Regex:       rulebuilder.Assignment([]string{"linear"}, `(?i)[a-f0-9]{32}`),
	Keywords:    []string{"linear"},
	FilterExpr:  `entropy(finding["secret"]) < 3.3 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `linearToken = "1f7b169c846f218ab552fa82fbf86758"`, "1f7b169c846f218ab552fa82fbf86758"),
	},
})
