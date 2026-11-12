package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

// Server and account tokens share the UUID shape. Try the read-only server
// endpoint first, then the account endpoint, and reject the token only when
// both authentication schemes return Postmark's documented 401 response.
var _ = rulebuilder.Add(config.Rule{
	ID:          "postmark-api-token.1",
	Confidence:  "high",
	Description: "Postmark server or account API token, which may allow access to email delivery and account configuration.",
	Regex:       rulebuilder.Assignment([]string{"postmark"}, `(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
	Keywords:    []string{"postmark"},
	ValidateExpr: `let server = http.get("https://api.postmarkapp.com/server", {
    "X-Postmark-Server-Token": finding["secret"],
    "Accept": "application/json"
  }); server.status == 200 && (server.body contains "\"ID\"") ? {
    "result": "valid",
    "metadata": {"type": "server"}
  } : (let account = http.get("https://api.postmarkapp.com/domains?count=1&offset=0", {
    "X-Postmark-Account-Token": finding["secret"],
    "Accept": "application/json"
  }); account.status == 200 ? {
    "result": "valid",
    "metadata": {"type": "account"}
  } : server.status == 401 && account.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(account))`,
	FilterExpr: rulebuilder.MinEntropy(3.0),
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "POSTMARK_SERVER_TOKEN=1f7b169c-846f-218a-b552-fa82fbf86758", "1f7b169c-846f-218a-b552-fa82fbf86758"),
		rulebuilder.Match("true positive 2", `postmark: "1f7b169c-846f-218a-b552-fa82fbf86758"`, "1f7b169c-846f-218a-b552-fa82fbf86758"),
		rulebuilder.Match("true positive 3", "postmark_account_api_token=1f7b169c-846f-218a-b552-fa82fbf86758", "1f7b169c-846f-218a-b552-fa82fbf86758"),
		rulebuilder.NoMatch("false positive 1", "SERVER_TOKEN=1f7b169c-846f-218a-b552-fa82fbf86758"),
		rulebuilder.NoMatch("false positive 2", "POSTMARK_SERVER_TOKEN=00000000-0000-0000-0000-000000000000"),
		rulebuilder.NoMatch("false positive 3", "POSTMARK_SERVER_TOKEN=short"),
	},
})
