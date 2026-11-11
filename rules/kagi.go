package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "kagi-api-key",
	Confidence:  "high",
	Description: "Detected a Kagi API key, which may expose Kagi API usage.",
	Regex:       Assignment([]string{"kagi"}, `(?i)`+AlphaNumericExtendedShort("11")+`\.`+AlphaNumericExtendedShort("43")),
	Keywords:    []string{"kagi"},
	ValidateExpr: `let r = http.get("https://kagi.com/api/v0/search?q=test", {
    "Authorization": "Bot " + finding["secret"]
  }); r.status == 200 && (r.body contains "\"data\":") && (r.body contains "\"results\":") ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: MinEntropy(3.5),
	Tests: []config.RuleTest{
		Match("true positive 1", "KAGI_API_KEY='AQAAUPJ-iQc.yLFDzC5RRHzPNDThhulREdoG0Bn3PiZMwJ6yqC6uJLE'", "AQAAUPJ-iQc.yLFDzC5RRHzPNDThhulREdoG0Bn3PiZMwJ6yqC6uJLE"),
	},
})
