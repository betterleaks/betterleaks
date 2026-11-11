package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "pagerduty-authorization-token.1",
	Confidence:  "high",
	Description: "PagerDuty authorization token, which may allow access to PagerDuty account and incident data.",
	Regex:       Assignment([]string{"pagerduty"}, `u\+[A-Za-z0-9_+-]{18}`),
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
	FilterExpr: MinEntropy(3.5),
	Tests: []config.RuleTest{
		Match("true positive 1", "PAGERDUTY_API_TOKEN=u+YiZCmtb+JDzrn7j7hg", "u+YiZCmtb+JDzrn7j7hg"),
		Match("true positive 2", `pagerduty authorization: "u+YiZCmtb+JDzrn7j7hg"`, "u+YiZCmtb+JDzrn7j7hg"),
		NoMatch("false positive 1", "API_TOKEN=u+YiZCmtb+JDzrn7j7hg"),
		NoMatch("false positive 2", "PAGERDUTY_API_TOKEN=u+short"),
		NoMatch("false positive 3", "PAGERDUTY_API_TOKEN=u+000000000000000000"),
	},
})
