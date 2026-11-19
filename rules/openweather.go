package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "openweather-api-key",
	Confidence:  "medium",
	Description: "OpenWeather API key.",
	Regex:       rulebuilder.Assignment([]string{"openweather", "pyowm"}, `[a-z0-9]{32}`),
	Keywords:    []string{"openweather", "pyowm"},
	ValidateExpr: `let r = http.get("https://api.openweathermap.org/data/2.5/forecast?q=London&appid=" + finding["secret"], {
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "OPENWEATHER_API_KEY=5fbbd6p84oe7ut4qrttebiwar77s63do", "5fbbd6p84oe7ut4qrttebiwar77s63do"),
		rulebuilder.Match("true positive 2", "pyowm='5fbbd6p84oe7ut4qrttebiwar77s63do'", "5fbbd6p84oe7ut4qrttebiwar77s63do"),
		rulebuilder.NoMatch("false positive 1", "OPENWEATHER_API_KEY=abcdef1234567890"),
		rulebuilder.NoMatch("false positive 2", "OPENWEATHER_API_KEY=00000000000000000000000000000000"),
	},
})
