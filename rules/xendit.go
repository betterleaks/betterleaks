package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "xendit-production-api-key.1",
	Confidence:  "high",
	Description: "Xendit production API key, which may allow access to payment and balance APIs.",
	Regex:       rulebuilder.Token(`xnd_production_[A-Za-z0-9]{56,72}`),
	Keywords:    []string{"xnd_production_"},
	ValidateExpr: `let r = http.get("https://api.xendit.co/balance", {
    "Authorization": "Basic " + base64.encode(bytes(finding["secret"] + ":")),
    "Accept": "application/json"
  }); r.status == 200 && (r.body contains "\"balance\"") ? {
    "result": "valid"
  } : r.status == 401 && (r.json?.error_code ?? "") == "INVALID_API_KEY" ? {
    "result": "invalid",
    "reason": "Invalid API key"
  } : validate.unknown(r)`,
	FilterExpr: rulebuilder.MinEntropy(3.0),
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "XENDIT_SECRET_KEY=xnd_production_RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klKiz9pyKl17ltLSvQmntzYlk", "xnd_production_RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klKiz9pyKl17ltLSvQmntzYlk"),
		rulebuilder.Match("true positive 2", "Authorization: Basic xnd_production_RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klKiz9pyKl17ltLSvQmntzYlk", "xnd_production_RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klKiz9pyKl17ltLSvQmntzYlk"),
		rulebuilder.NoMatch("false positive 1", "XENDIT_SECRET_KEY=xnd_development_A1b2C3d4E5f6G7h8J9kLmNoPqRsTuVwXyZ0123456789AbCdEfGhJkLm"),
		rulebuilder.NoMatch("false positive 2", "XENDIT_SECRET_KEY=xnd_production_short"),
		rulebuilder.NoMatch("false positive 3", "XENDIT_SECRET_KEY=xnd_production_0000000000000000000000000000000000000000000000000000000000000000"),
	},
})
