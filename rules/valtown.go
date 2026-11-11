package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "val-town-api-token.1",
	Confidence:  "high",
	Description: "Val Town API token.",
	Regex:       Token(`vtwn_[A-Za-z0-9_-]{20,80}`),
	Keywords:    []string{"vtwn_"},
	ValidateExpr: `let r = http.get("https://api.val.town/v1/me", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 && (r.body contains "\"id\"") ? {
    "result": "valid"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) < 3.5
|| !matchesAny(finding["secret"], ["^(?:[^0-9]*[0-9]){2}"])`,
	Tests: []config.RuleTest{
		Match("true positive 1", "VALTOWN_TOKEN=vtwn_12WE6v05tg7Z5jXlNPAK_XEPcHzfjsqr", "vtwn_12WE6v05tg7Z5jXlNPAK_XEPcHzfjsqr"),
		NoMatch("false positive 1", "VALTOWN_TOKEN=vtwn_short"),
		NoMatch("false positive 2", "VALTOWN_TOKEN=vtwn_AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEf"),
	},
})
