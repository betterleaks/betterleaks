package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "mercury-production-api-token",
	Confidence:  "high",
	Description: "Mercury production API token.",
	Regex:       Token(`mercury_production_[a-z]{3,6}_[A-Za-z0-9]{40,50}_yrucrem`),
	Keywords:    []string{"mercury_production_"},
	ValidateExpr: `let r = http.get("https://api.mercury.com/api/v1/accounts", {
    "Authorization": "Bearer secret-token:" + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: MinEntropy(3.5),
	Tests: []config.RuleTest{
		Match("true positive 1", "Authorization: Bearer secret-token:mercury_production_wma_5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar_yrucrem", "mercury_production_wma_5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar_yrucrem"),
		NoMatch("false positive 1", "MERCURY_API_TOKEN=mercury_production_wma_short_yrucrem"),
		NoMatch("false positive 2", "MERCURY_API_TOKEN=mercury_sandbox_rma_24pnbcT7NygLbpJPr4xBuSuBDpo6tK89S8u3ERYn3FXVz_yrucrem"),
	},
})
