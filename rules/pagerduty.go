package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "pagerduty-authorization-token.1",
	Confidence:  "high",
	Description: "PagerDuty authorization token, which may allow access to PagerDuty account and incident data.",
	Regex:       rulebuilder.Assignment([]string{"pagerduty"}, `u\+[A-Za-z0-9_+-]{18}`),
	Keywords:    []string{"pagerduty"},
	ValidateExpr: `let r = http.get("https://api.pagerduty.com/users?limit=1", {
    "Authorization": "Token token=" + finding["secret"],
    "Accept": "application/vnd.pagerduty+json;version=2"
  }); r.status == 200 && (r.body contains "\"users\"") ? {
    "result": "valid"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: rulebuilder.MinEntropy(3.5),
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "PAGERDUTY_API_TOKEN=u+YiZCmtb+JDzrn7j7hg", "u+YiZCmtb+JDzrn7j7hg"),
		rulebuilder.Match("true positive 2", `pagerduty authorization: "u+YiZCmtb+JDzrn7j7hg"`, "u+YiZCmtb+JDzrn7j7hg"),
		rulebuilder.NoMatch("false positive 1", "API_TOKEN=u+YiZCmtb+JDzrn7j7hg"),
		rulebuilder.NoMatch("false positive 2", "PAGERDUTY_API_TOKEN=u+short"),
		rulebuilder.NoMatch("false positive 3", "PAGERDUTY_API_TOKEN=u+000000000000000000"),
	},
})
