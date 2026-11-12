package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

// Current ngrok API keys and agent authtokens share this family. Passing an
// agent token to the API returns ERR_NGROK_206, which proves the credential
// is live without opening a tunnel or mutating account state.
var _ = rulebuilder.Add(config.Rule{
	ID:          "ngrok-api-key.1",
	Confidence:  "high",
	Description: "ngrok API key or agent authtoken, which may allow tunnel access or account administration.",
	Regex: rulebuilder.Assignment(
		[]string{`ngrok[_. -]*(?:(?:api|agent)[_. -]*)?(?:secret|key|token|authtoken)`},
		`2[A-Za-z0-9]{26}_[0-9][A-Za-z0-9]{20}`,
	),
	Keywords: []string{"ngrok"},
	ValidateExpr: `let r = http.get("https://api.ngrok.com/agent_ingresses", {
    "Authorization": "Bearer " + finding["secret"],
    "ngrok-version": "2",
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status == 400 && (r.body contains "ERR_NGROK_206") ? {
    "result": "valid",
    "reason": "Live ngrok agent authtoken"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Authentication failed"
  } : validate.unknown(r)`,
	FilterExpr: rulebuilder.MinEntropy(3.5),
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "NGROK_AUTHTOKEN=2RFbD56TI2smTyVsGd5Xav0yu99_1RFbD56TI2smTyVsGd5Xa", "2RFbD56TI2smTyVsGd5Xav0yu99_1RFbD56TI2smTyVsGd5Xa"),
		rulebuilder.Match("true positive 2", `ngrok api key: "2RFbD56TI2smTyVsGd5Xav0yu99_1RFbD56TI2smTyVsGd5Xa"`, "2RFbD56TI2smTyVsGd5Xav0yu99_1RFbD56TI2smTyVsGd5Xa"),
		rulebuilder.NoMatch("false positive 1", "AUTHTOKEN=2RFbD56TI2smTyVsGd5Xav0yu99_1RFbD56TI2smTyVsGd5Xa"),
		rulebuilder.NoMatch("false positive 2", "NGROK_AUTHTOKEN=2short_1short"),
		rulebuilder.NoMatch("false positive 3", "NGROK_AUTHTOKEN=200000000000000000000000000_100000000000000000000"),
	},
})
