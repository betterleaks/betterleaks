package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "klaviyo-api-key",
	Confidence:  "high",
	Description: "Detected a Klaviyo API key, which may expose Klaviyo account and marketing data.",
	Regex:       Assignment([]string{"klaviyo"}, `(?i)pk_`+AlphaNumeric("34")),
	Keywords:    []string{"klaviyo"},
	ValidateExpr: `let r = http.get("https://a.klaviyo.com/api/accounts", {
    "Revision": "2023-02-22",
    "Authorization": "Klaviyo-API-Key " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 && (r.body contains "\"data\"") ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: MinEntropy(3.5),
	Tests: []config.RuleTest{
		Match("true positive 1", "klaviyo_key = pk_abcd1234fghij5678klmn9012opqr3456s", "pk_abcd1234fghij5678klmn9012opqr3456s"),
		Match("true positive 2", "KLAVIYO_API_KEY=pk_ABCd1234fghij5678klmn9012opqr3456s", "pk_ABCd1234fghij5678klmn9012opqr3456s"),
	},
})
