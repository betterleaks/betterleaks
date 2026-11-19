package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "weatherstack-api-key.1",
	Confidence:  "medium",
	Description: "Weatherstack API key.",
	Regex: rulebuilder.Assignment(
		[]string{`weatherstack(?:[_. -]*(?:api))?[_. -]*(?:secret|key|token)`},
		`[0-9a-z]{32}`,
	),
	Keywords: []string{"weatherstack"},
	ValidateExpr: `let r = http.get("https://api.weatherstack.com/current?access_key=" + finding["secret"] + "&query=Los%20Angeles", {
    "Accept": "application/json"
  }); r.status == 200 && ((r.body contains "\"location\"") || (r.body contains "Access Restricted - Your current Subscription Plan does not support HTTPS Encryption")) ? {
    "result": "valid"
  } : r.status == 401 && (r.body contains "\"invalid_access_key\"") ? {
    "result": "invalid",
    "reason": "Invalid access key"
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) < 3.3 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "WEATHERSTACK_API_KEY=5fbbd6p84oe7ut4qrttebiwar77s63do", "5fbbd6p84oe7ut4qrttebiwar77s63do"),
		rulebuilder.NoMatch("false positive 1", "API_KEY=abcdef0123456789abcdef0123456789"),
		rulebuilder.NoMatch("false positive 2", "WEATHERSTACK_API_KEY=short"),
		rulebuilder.NoMatch("false positive 3", "WEATHERSTACK_API_KEY=00000000000000000000000000000000"),
	},
})
