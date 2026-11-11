package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "sslmate-api-key.1",
	Confidence:  "high",
	Description: "SSLMate API key.",
	Regex: Assignment(
		[]string{`sslmate(?:[_. -]*(?:api))?[_. -]*(?:secret|key|token)`},
		`[A-Za-z0-9]{36}`,
	),
	Keywords: []string{"sslmate"},
	ValidateExpr: `let r = http.get("https://sslmate.com/api/v2/certs/example.com", {
    "Authorization": "Basic " + base64.encode(bytes(finding["secret"] + ":")),
    "Accept": "application/json"
  }); r.status == 200 && (r.body contains "\"cn\"")
    && (r.body contains "\"exists\"") ? {
    "result": "valid"
  } : r.status == 401 && (r.json?.reason ?? "") == "bad_credentials" ? {
    "result": "invalid",
    "reason": "Bad credentials"
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("true positive 1", "SSLMATE_API_KEY=5fbbd6p84oe7ut4qrttebiwar77s63donnl8", "5fbbd6p84oe7ut4qrttebiwar77s63donnl8"),
		NoMatch("false positive 1", "API_KEY=ABCDEFGHIJ1234567890ABCDEFGHIJ123456"),
		NoMatch("false positive 2", "SSLMATE_API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
	},
})
