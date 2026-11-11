package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "apollo-api-key.1",
	Confidence:  "medium",
	Description: "Apollo.io API key, which may allow access to sales intelligence and engagement data.",
	Regex:       Assignment([]string{"apollo"}, `[A-Za-z0-9_-]{22}`),
	Keywords:    []string{"apollo"},
	ValidateExpr: `let r = http.post("https://api.apollo.io/api/v1/mixed_people/api_search", {
    "X-Api-Key": finding["secret"],
    "Accept": "application/json",
    "Content-Type": "application/json"
  }, "{\"page\":1,\"per_page\":1}"); r.status == 200 && (r.body contains "\"total_entries\"") ? {
    "result": "valid"
  } : r.status == 403 && (r.body contains "API_INACCESSIBLE") ? {
    "result": "valid",
    "reason": "Authenticated but this API is unavailable to the account"
  } : r.status == 401 && (r.body contains "Invalid API key") ? {
    "result": "invalid",
    "reason": "Invalid API key"
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) < 3.0 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("true positive 1", "APOLLO_API_KEY=WE6v05tg7Z5jXlNPAK_XEP", "WE6v05tg7Z5jXlNPAK_XEP"),
		Match("true positive 2", `apollo.io token: "WE6v05tg7Z5jXlNPAK_XEP"`, "WE6v05tg7Z5jXlNPAK_XEP"),
		NoMatch("false positive 1", "API_KEY=WE6v05tg7Z5jXlNPAK_XEP"),
		NoMatch("false positive 2", "APOLLO_API_KEY=abcdefghijklmnopqrstuv"),
		NoMatch("false positive 3", "APOLLO_API_KEY=short"),
	},
})
