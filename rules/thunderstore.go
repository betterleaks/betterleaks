package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "thunderstore-api-token.1",
	Confidence:  "high",
	Description: "Thunderstore API token.",
	Regex:       Token(`tss_[A-Za-z0-9_-]{20,80}`),
	Keywords:    []string{"tss_"},
	ValidateExpr: `let r = http.get("https://thunderstore.io/api/experimental/current-user/", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 && (r.body contains "\"username\"") ? {
    "result": "valid"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Invalid Service Account token"
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) < 3.5
|| !matchesAny(finding["secret"], ["^(?:[^0-9]*[0-9]){2}"])`,
	Tests: []config.RuleTest{
		Match("true positive 1", "THUNDERSTORE_TOKEN=tss_12WE6v05tg7Z5jXlNPAK_XEPcHzfjsqr", "tss_12WE6v05tg7Z5jXlNPAK_XEPcHzfjsqr"),
		NoMatch("false positive 1", "tss_short"),
		NoMatch("false positive 2", "tss_AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEf"),
	},
})
