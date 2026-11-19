package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

// https://developer.clickup.com/reference/getauthorizeduser
const clickupValidateExpr = `let r = http.get("https://api.clickup.com/api/v2/user", {
  "Authorization": finding["secret"],
  "Accept": "application/json"
});
r.status == 200 && type(r.json) == "map" && type(r.json?.user) == "map" && (r.json?.user?.id ?? "") != "" ? {
  "result": "valid",
  "analysis": {
    "identity": {
      "id": string(r.json?.user?.id ?? ""),
      "username": string(r.json?.user?.username ?? ""),
      "email": string(r.json?.user?.email ?? "")
    },
    "metadata": {}
  },
  "metadata": {
    "username": string(r.json?.user?.username ?? ""),
    "email": string(r.json?.user?.email ?? "")
  }
} : r.status == 401 ? {
  "result": "invalid", "reason": "Unauthorized"
} : validate.unknown(r)`

const clickupAnalyzeExpr = rulebuilder.IdentityOnlyAnalyzeExpr

var _ = rulebuilder.Add(config.Rule{
	ID:           "clickup-personal-api-token",
	Confidence:   "high",
	Description:  "Detected a ClickUp personal API token, which may allow unauthorized access to ClickUp workspaces and user data.",
	Regex:        rulebuilder.Assignment([]string{"clickup"}, `(?i)pk_[0-9]{8,9}_[a-z0-9]{32}`),
	Keywords:     []string{"clickup"},
	ValidateExpr: clickupValidateExpr,
	AnalyzeExpr:  clickupAnalyzeExpr,
	FilterExpr:   rulebuilder.MinEntropy(3.5),
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "CLICKUP_API_TOKEN=pk_204249739_138RCYNYCVO0GRJ8INODHFRMXN0QSV75", "pk_204249739_138RCYNYCVO0GRJ8INODHFRMXN0QSV75"),
		rulebuilder.Match("true positive 2", `clickup_token: "pk_204249739_GSJCPRLQEX43KH4WN8093RZ9DW3CJGM4"`, "pk_204249739_GSJCPRLQEX43KH4WN8093RZ9DW3CJGM4"),
		rulebuilder.NoMatch("false positive 1", "API_TOKEN=pk_204249739_138RCYNYCVO0GRJ8INODHFRMXN0QSV75"),
		rulebuilder.NoMatch("false positive 2", "CLICKUP_API_TOKEN=pk_2042497_138RCYNYCVO0GRJ8INODHFRMXN0QSV75"),
	},
})
