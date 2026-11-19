package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "daytona-api-key",
	Confidence:  "high",
	Description: "Detected a Daytona API key, which may allow access to Daytona workspace management and development environment orchestration.",
	Regex:       rulebuilder.Token(`dtn_[a-f0-9]{64}`),
	Keywords:    []string{"dtn_"},
	ValidateExpr: `let r = http.get("https://app.daytona.io/api/api-keys/current", {"Authorization": "Bearer " + finding["secret"], "User-Agent": "Go-http-client/1.1"});
(r.status in [200]) ? {
    "result": "valid",
    "analysis": {
      "user_id": string(r.json?.userId ?? ""),
      "organization_id": string(r.json?.organizationId ?? ""),
    }
  } :
(r.status in [401]) ? {"result": "invalid"} :
validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) <= 3.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("shape 1", `token = "dtn_e64cce737ed89b1396767201aaf4d58d11bf7e0622982b57fa8697a3002a111e"`, `dtn_e64cce737ed89b1396767201aaf4d58d11bf7e0622982b57fa8697a3002a111e`),
		rulebuilder.NoMatch("near miss 1", `token = "dtn_633600a2f1ffc25873b01e1569c71300ae4cba766c2cdc991ca02d7b2ad006f"`),
	},
})
