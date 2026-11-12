package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "jumpcloud-api-key",
	Confidence:  "high",
	Description: "Detected a JumpCloud API key, which may expose JumpCloud directory data.",
	Regex:       rulebuilder.Assignment([]string{"jumpcloud"}, `(?i)`+rulebuilder.AlphaNumeric("40")),
	Keywords:    []string{"jumpcloud"},
	ValidateExpr: `let r = http.get("https://console.jumpcloud.com/api/systemusers?limit=1&skip=0", {
    "x-api-key": finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 && (r.body contains "\"results\"") ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "jumpcloud_api_key=1a2b3c4d5e6f7g8h9i0j1a2b3c4d5e6f7g8h9i0j", "1a2b3c4d5e6f7g8h9i0j1a2b3c4d5e6f7g8h9i0j"),
		rulebuilder.Match("true positive 2", "JUMPCLOUD_SECRET=k9l8m7n6o5p4q3r2s1t0k9l8m7n6o5p4q3r2s1t0", "k9l8m7n6o5p4q3r2s1t0k9l8m7n6o5p4q3r2s1t0"),
	},
})
