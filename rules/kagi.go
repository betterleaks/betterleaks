package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "kagi-api-key",
	Confidence:  "high",
	Description: "Detected a Kagi API key, which may expose Kagi API usage.",
	Regex:       rulebuilder.Assignment([]string{"kagi"}, `(?i)[a-z0-9_-]{11}\.[a-z0-9_-]{43}`),
	Keywords:    []string{"kagi"},
	ValidateExpr: `let r = http.get("https://kagi.com/api/v0/search?q=test", {
    "Authorization": "Bot " + finding["secret"]
  }); r.status == 200 && (r.body contains "\"data\":") && (r.body contains "\"results\":") ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: rulebuilder.MinEntropy(3.5),
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "KAGI_API_KEY='AQAAUPJ-iQc.yLFDzC5RRHzPNDThhulREdoG0Bn3PiZMwJ6yqC6uJLE'", "AQAAUPJ-iQc.yLFDzC5RRHzPNDThhulREdoG0Bn3PiZMwJ6yqC6uJLE"),
	},
})
