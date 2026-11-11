package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "datadog-api-key",
	Confidence:  "high",
	Description: "Detected a Datadog API key, potentially risking monitoring and analytics data exposure and manipulation.",
	Regex: Assignment([]string{"datadog"},
		`(?i)`+AlphaNumeric("32")),
	Keywords: []string{
		"datadog",
	},
	ValidateExpr: `let r = http.get("https://api.datadoghq.com/api/v1/validate", {
    "Accept": "application/json",
    "DD-API-KEY": finding["secret"]
  }); r.status == 200 && !(r.body contains "\"Forbidden\"") ? {
    "result": "valid"
  } : r.status in [401, 403] || (r.body contains "\"Forbidden\"") ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: MinEntropy(3.5),
	Tests: []config.RuleTest{
		Match("datadog assignment", `datadogToken = "5fbbd6p84oe7ut4qrttebiwar77s63do"`, "5fbbd6p84oe7ut4qrttebiwar77s63do"),
		Match("true positive 1", "DATADOG_API_KEY=0024a29224affe29d173c0bf99e5a89d", "0024a29224affe29d173c0bf99e5a89d"),
	},
})

var _ = Add(config.Rule{
	ID:          "datadog-application-key",
	Confidence:  "high",
	Description: "Detected a Datadog application key, which may expose Datadog account and monitoring data when paired with an API key.",
	Regex:       Assignment([]string{"datadog"}, `(?i)[A-Za-z0-9-]{40}`),
	Keywords: []string{
		"datadog",
	},
	FilterExpr: MinEntropy(3.5),
	Tests: []config.RuleTest{
		Match("true positive 1", "DATADOG_APPLICATION_KEY=abcDEF0123456789abcDEF0123456789abcDEF01", "abcDEF0123456789abcDEF0123456789abcDEF01"),
	},
})
