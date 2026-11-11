package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "telnyx-api-v2-key.1",
	Confidence:  "high",
	Description: "Telnyx API v2 key.",
	Regex: Assignment(
		[]string{`telnyx(?:[_. -]*(?:api))?[_. -]*(?:secret|key|token)`},
		`KEY[0-9A-Za-z_-]{55}`,
	),
	Keywords: []string{"telnyx"},
	ValidateExpr: `let r = http.get("https://api.telnyx.com/v2/balance", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 && (r.body contains "\"balance\"") ? {
    "result": "valid"
  } : r.status == 403 ? {
    "result": "valid",
    "reason": "Authenticated but balance access is restricted"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Authentication failed"
  } : validate.unknown(r)`,
	FilterExpr: MinEntropy(3.5),
	Tests: []config.RuleTest{
		Match("true positive 1", "TELNYX_API_KEY=KEY017D98C041711C2B8B6F5A2E50702659_hwntpZaC4XD1OEQEaKWydG", "KEY017D98C041711C2B8B6F5A2E50702659_hwntpZaC4XD1OEQEaKWydG"),
		NoMatch("false positive 1", "API_KEY=KEY017D98C041711C2B8B6F5A2E50702659_hwntpZaC4XD1OEQEaKWydG"),
		NoMatch("false positive 2", "TELNYX_API_KEY=KEY_short"),
		NoMatch("false positive 3", "TELNYX_API_KEY=KEYxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
	},
})
