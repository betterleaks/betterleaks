package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "samsara-api-token.1",
	Confidence:  "high",
	Description: "Samsara API token.",
	Regex:       rulebuilder.Token(`samsara_api_[A-Za-z0-9]{26,32}`),
	Keywords:    []string{"samsara_api_"},
	ValidateExpr: `let r = http.get("https://api.samsara.com/fleet/vehicles", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status == 403 ? {
    "result": "valid",
    "reason": "Authenticated but vehicle access is restricted"
  } : r.status == 401 && (r.json?.message ?? "") == "invalid token" ? {
    "result": "invalid",
    "reason": "Invalid token"
  } : validate.unknown(r)`,
	FilterExpr: rulebuilder.MinEntropy(3.0),
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "SAMSARA_API_TOKEN=samsara_api_5fbbd6p84oe7ut4qrttebiwar77s63", "samsara_api_5fbbd6p84oe7ut4qrttebiwar77s63"),
		rulebuilder.NoMatch("false positive 1", "SAMSARA_API_TOKEN=samsara_api_short"),
		rulebuilder.NoMatch("false positive 2", "SAMSARA_API_TOKEN=samsara_api_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
	},
})
