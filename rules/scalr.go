package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "scalr-api-access-token.1",
	Confidence:  "high",
	Description: "Scalr API access token.",
	Regex: Assignment(
		[]string{`scalr(?:[_. -]*(?:api|access))?[_. -]*(?:secret|key|token)`},
		`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.eyJpc3MiOiJ1c2VyIiwianRpIjoiYXQt[A-Za-z0-9_-]{20,40}\.[A-Za-z0-9_-]{43}`,
	),
	Keywords: []string{"scalr"},
	ValidateExpr: `let r = http.get("https://scalr.io/api/iacp/v3/accounts", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/vnd.api+json"
  }); r.status == 200 && (r.body contains "\"data\"") ? {
    "result": "valid"
  } : r.status == 403 ? {
    "result": "valid",
    "reason": "Authenticated but account access is restricted"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: MinEntropy(3.5),
	Tests: []config.RuleTest{
		Match("true positive 1", `SCALR_KEY="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ1c2VyIiwianRpIjoiYXQtdzFwNWtvN2h2ODh0bGVzcDAifQ.VCPHD8dI5RAO4yexSrfk7mhrBu1KFnGU3Rm2zwApplF"`, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ1c2VyIiwianRpIjoiYXQtdzFwNWtvN2h2ODh0bGVzcDAifQ.VCPHD8dI5RAO4yexSrfk7mhrBu1KFnGU3Rm2zwApplF"),
		NoMatch("false positive 1", `OTHER_JWT="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ1c2VyIiwianRpIjoiYXQtdzFwNWtvN2h2ODh0bGVzcDAifQ.VCPHD8dI5RAO4yexSrfk7mhrBu1KFnGU3Rm2zwApplF"`),
		NoMatch("false positive 2", "SCALR_KEY=eyJhbGciOiJIUzI1NiJ9.short.token"),
	},
})
