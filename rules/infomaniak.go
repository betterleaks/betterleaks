package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "infomaniak-api-token",
	Confidence:  "high",
	Description: "Detected an Infomaniak API token, which may expose hosting, mail, and cloud services to unauthorized access.",
	Regex:       rulebuilder.Assignment([]string{"infomaniak"}, `(?i)[A-Za-z0-9_\-]{60,100}`),
	Keywords:    []string{"infomaniak"},
	FilterExpr:  `entropy(finding["secret"]) < 4.0 || tokenRatio(finding["secret"]) >= 2.5`,
	ValidateExpr: `let r = http.get("https://api.infomaniak.com/1/profile", {
    "Authorization": "Bearer " + finding["secret"]
  }); r.status == 200 && (r.body contains '"result"') ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `infomaniakToken = "WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG7ubf2TxReZd1UXAc"`, "WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG7ubf2TxReZd1UXAc"),
		rulebuilder.NoMatch("Too short", `infomaniak_token = "AYF5lSh3c7Xy"`),
	},
})
