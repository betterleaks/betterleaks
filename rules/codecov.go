package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "codecov-access-token",
	Confidence:  "high",
	Description: "Found a pattern resembling a Codecov Access Token, posing a risk of unauthorized access to code coverage reports and sensitive data.",
	Regex:       Assignment([]string{"codecov"}, `(?i)[A-Z0-9-]{36}`),
	Keywords:    []string{"codecov"},
	ValidateExpr: `let r = http.get("https://api.codecov.io/api/v2/github/", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 && (r.body contains "\"count\":") ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("true positive 1", "codecov_token = 52acf265-3fc6-4ecd-304a-15940bd04653", "52acf265-3fc6-4ecd-304a-15940bd04653"),
		NoMatch("false positive 1", "codecov_token = short"),
		NoMatch("false positive 2", "token = 52acf265-3fc6-4ecd-304a-15940bd04653"),
	},
})
