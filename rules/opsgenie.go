package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

// Opsgenie supports US and EU service regions. Existing REST credentials
// remain usable until the service's announced end-of-support date, so both
// fixed provider hosts are checked before rejecting a key.
var _ = rulebuilder.Add(config.Rule{
	ID:          "opsgenie-api-key.1",
	Confidence:  "high",
	Description: "Opsgenie API key, which may allow access to alerts, incidents, and account configuration.",
	Regex:       rulebuilder.Assignment([]string{"opsgenie"}, `(?i)`+rulebuilder.Hex8_4_4_4_12()),
	Keywords:    []string{"opsgenie"},
	ValidateExpr: `let us = http.get("https://api.opsgenie.com/v2/account", {
    "Authorization": "GenieKey " + finding["secret"],
    "Accept": "application/json"
  }); us.status in [200, 403] ? {
    "result": "valid",
    "metadata": {"region": "us"}
  } : (let eu = http.get("https://api.eu.opsgenie.com/v2/account", {
    "Authorization": "GenieKey " + finding["secret"],
    "Accept": "application/json"
  }); eu.status in [200, 403] ? {
    "result": "valid",
    "metadata": {"region": "eu"}
  } : us.status == 401 && eu.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(eu))`,
	FilterExpr: rulebuilder.MinEntropy(3.0),
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "OPSGENIE_API_KEY=1f7b169c-846f-218a-b552-fa82fbf86758", "1f7b169c-846f-218a-b552-fa82fbf86758"),
		rulebuilder.Match("true positive 2", `opsgenie token: "1f7b169c-846f-218a-b552-fa82fbf86758"`, "1f7b169c-846f-218a-b552-fa82fbf86758"),
		rulebuilder.NoMatch("false positive 1", "API_KEY=1f7b169c-846f-218a-b552-fa82fbf86758"),
		rulebuilder.NoMatch("false positive 2", "OPSGENIE_API_KEY=00000000-0000-0000-0000-000000000000"),
		rulebuilder.NoMatch("false positive 3", "OPSGENIE_API_KEY=short"),
	},
})
