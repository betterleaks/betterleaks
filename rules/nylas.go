package rules

import "github.com/betterleaks/betterleaks/v2/config"

// Current v3 API keys have a stable provider prefix and are bound to either
// the US or EU data-residency API. Only two fixed Nylas hosts are contacted.
var _ = Add(config.Rule{
	ID:          "nylas-api-key.1",
	Confidence:  "high",
	Description: "Nylas API key, which may allow application-level access to connected email, calendar, and contact data.",
	Regex:       Token(`nyk_[A-Za-z0-9]{67}`),
	Keywords:    []string{"nyk_"},
	ValidateExpr: `let us = http.get("https://api.us.nylas.com/v3/webhooks?limit=1", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); us.status in [200, 403] ? {
    "result": "valid",
    "metadata": {"region": "us"}
  } : (let eu = http.get("https://api.eu.nylas.com/v3/webhooks?limit=1", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); eu.status in [200, 403] ? {
    "result": "valid",
    "metadata": {"region": "eu"}
  } : us.status == 401 && eu.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(eu))`,
	FilterExpr: MinEntropy(3.5),
	Tests: []config.RuleTest{
		Match("true positive 1", "NYLAS_API_KEY=nyk_RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klKiz9pyKl17ltLSvQmntzYlkmif", "nyk_RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klKiz9pyKl17ltLSvQmntzYlkmif"),
		Match("true positive 2", "Authorization: Bearer nyk_RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klKiz9pyKl17ltLSvQmntzYlkmif", "nyk_RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klKiz9pyKl17ltLSvQmntzYlkmif"),
		NoMatch("false positive 1", "NYLAS_API_KEY=nyk_short"),
		NoMatch("false positive 2", "NYLAS_API_KEY=nyk_0000000000000000000000000000000000000000000000000000000000000000000"),
		NoMatch("false positive 3", "NYLAS_API_KEY=RFbD56TI2smTyVsGd5Xav0yu99ZAMP"),
	},
})
