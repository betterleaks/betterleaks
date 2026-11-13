package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

const devCycleValidationExpr = `let r = http.post("https://bucketing-api.devcycle.com/v1/variables", {
    "Authorization": "Bearer " + finding["secret"],
    "Content-Type": "application/json"
  }, "{\"user_id\":\"betterleaks-validation-user\"}"); r.status == 200 ? {
    "result": "valid"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`

var _ = rulebuilder.Add(config.Rule{
	ID:           "devcycle-server-sdk-key",
	Confidence:   "high",
	Description:  "DevCycle server SDK key.",
	Regex:        `\b(dvc_server_[A-Za-z0-9]{8,32})`,
	Keywords:     []string{"dvc_server_"},
	ValidateExpr: devCycleValidationExpr,
	FilterExpr:   rulebuilder.MinEntropy(3.0),
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", `devcycle_api_token = "dvc_server_5fbbd6p84oe7ut4qrttebiwa"`, "dvc_server_5fbbd6p84oe7ut4qrttebiwa"),
		rulebuilder.NoMatch("false positive 1", "dvc_server_short"),
	},
})
