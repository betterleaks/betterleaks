package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "midtrans-production-server-client-key",
	Confidence:  "high",
	Description: "Midtrans production server or client key.",
	Regex: Assignment(
		[]string{`midtrans`, `mid[_-]?`},
		`(?i)Mid-(?:server|client)-[A-Za-z0-9_]{10,20}`,
	),
	Keywords: []string{"mid-server-", "mid-client-"},
	ValidateExpr: `let r = http.get("https://api.midtrans.com/v2/betterleaks-validation-nonexistent/status", {
    "Authorization": "Basic " + base64.encode(bytes(finding["secret"] + ":")),
    "Accept": "application/json"
  }); r.status == 200 || (r.status == 404
    && (r.json?.status_code ?? "") == "404"
    && (r.json?.status_message ?? "") == "The requested resource is not found") ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: MinEntropy(2.8),
	Tests: []config.RuleTest{
		Match("true positive 1", "MIDTRANS_SERVER_KEY=Mid-server-eoTtDxpQ4FWYcbMq", "Mid-server-eoTtDxpQ4FWYcbMq"),
		Match("true positive 2", "midtrans.client_key='Mid-client-eoTtDxpQ4FWYcbMq'", "Mid-client-eoTtDxpQ4FWYcbMq"),
		NoMatch("false positive 1", "MIDTRANS_SERVER_KEY=Mid-server-short"),
		NoMatch("false positive 2", "MIDTRANS_CLIENT_KEY=SB-Mid-client-Xk93PcDP8pMKfhY2"),
	},
})
