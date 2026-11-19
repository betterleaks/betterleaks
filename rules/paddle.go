package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "paddle-live-api-key",
	Confidence:  "high",
	Description: "Paddle live API key.",
	Regex:       rulebuilder.Token(`pdl_live_apikey_[a-z0-9]{26}_[A-Za-z0-9]{22}_[A-Za-z0-9]{3}`),
	Keywords:    []string{"pdl_live_apikey_"},
	ValidateExpr: `let r = http.get("https://api.paddle.com/event-types", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status == 401 || (r.status == 403
    && (r.json?.error?.code ?? "") in ["authentication_malformed", "authentication_invalid"]) ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: rulebuilder.MinEntropy(3.5),
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "PADDLE_API_KEY=pdl_live_apikey_5fbbd6p84oe7ut4qrttebiwar7_RFbD56TI2smTyVsGd5Xav0_RFb", "pdl_live_apikey_5fbbd6p84oe7ut4qrttebiwar7_RFbD56TI2smTyVsGd5Xav0_RFb"),
		rulebuilder.NoMatch("false positive 1", "PADDLE_API_KEY=pdl_sdbx_apikey_01kps076233qscw38dxz320d0e_Ab3D5fGb7Jk9LmNpQrStUv_X2z"),
		rulebuilder.NoMatch("false positive 2", "PADDLE_API_KEY=pdl_live_apikey_short"),
	},
})
