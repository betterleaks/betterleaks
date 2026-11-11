package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "mailersend-api-token",
	Confidence:  "high",
	Description: "MailerSend API token.",
	Regex:       Token(`mlsn\.[A-Za-z0-9]{30,100}`),
	Keywords:    []string{"mlsn."},
	ValidateExpr: `let r = http.get("https://api.mailersend.com/v1/api-quota", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: MinEntropy(3.5),
	Tests: []config.RuleTest{
		Match("true positive 1", "MAILERSEND_API_TOKEN=mlsn.5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rys", "mlsn.5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rys"),
		NoMatch("false positive 1", "MAILERSEND_API_TOKEN=mlsn.short"),
		NoMatch("false positive 2", "MAILERSEND_API_TOKEN=mlsn.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
	},
})
