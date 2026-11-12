package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "gumroad-access-token",
	Confidence:  "high",
	Description: "Detected a Gumroad access token, which may expose Gumroad account and product data.",
	Regex:       rulebuilder.Assignment([]string{"gumroad"}, `(?i)(?:[a-f0-9]{64}|[A-Za-z0-9-]{43})`),
	Keywords:    []string{"gumroad"},
	ValidateExpr: `let r = http.get("https://api.gumroad.com/v2/user?access_token=" + finding["secret"], {
    "Accept": "application/json"
  }); r.status == 200 && (r.body contains "\"success\":true") && (r.body contains "\"user\"") ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "gumroad_access_token=abf11e4ab2850ffd50ef690257f7a1c998a443059513d1a4826f2b3159620505", "abf11e4ab2850ffd50ef690257f7a1c998a443059513d1a4826f2b3159620505"),
		rulebuilder.Match("true positive 2", "gumroadPRIVATE=abf11e4ab2850ffd50ef690257f7a1c998a443059513d1a4826f2b3159620505", "abf11e4ab2850ffd50ef690257f7a1c998a443059513d1a4826f2b3159620505"),
	},
})
