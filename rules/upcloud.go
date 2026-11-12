package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "upcloud-api-token",
	Confidence:  "high",
	Description: "Identified an UpCloud API token, which may expose cloud infrastructure resources to unauthorized access.",
	Regex:       rulebuilder.Token(`ucat_[0-9A-Za-z]{24,32}`),
	Keywords:    []string{"ucat_"},
	FilterExpr:  rulebuilder.MinEntropy(3.0),
	ValidateExpr: `let r = http.get("https://api.upcloud.com/1.3/account", {
    "Authorization": "Bearer " + finding["secret"]
  }); r.status == 200 && (r.body contains '"account"') ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", `upcloud_api_token = "ucat_5FBBD6P84OE7UT4QRTTEBIWAR7"`, "ucat_5FBBD6P84OE7UT4QRTTEBIWAR7"),
		rulebuilder.NoMatch("Too short", "upcloud_token = ucat_01DQE3"),
		rulebuilder.NoMatch("Wrong prefix", "upcloud_token = uca_01DQE3AJDEBFEKECFM558TGH2F"),
	},
})
