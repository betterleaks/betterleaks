package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "smartbear-bitbar-api-key",
	Confidence:  "medium",
	Description: "Detected a SmartBear Bitbar API key, which may allow access to cloud testing infrastructure and device testing APIs.",
	Regex:       rulebuilder.Assignment([]string{"bitbar"}, `[A-Za-z0-9]{32}`),
	Keywords:    []string{"bitbar"},
	ValidateExpr: `let r = http.get("https://cloud.bitbar.com/api/v2/me", {"Authorization": "Basic " + base64.encode(bytes(finding["secret"] + ":"))});
(r.status in [200]) ? {
    "result": "valid",
    "analysis": {
      "account_id": string(r.json?.accountId ?? ""),
      "user_id": string(r.json?.id ?? ""),
    }
  } :
(r.status in [401]) ? {"result": "invalid"} :
validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) <= 3.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("shape 1", `bitbar = "88hxqbSg1YjWcbbNpYgLJOnBh2xPAGS6"`, `88hxqbSg1YjWcbbNpYgLJOnBh2xPAGS6`),
		rulebuilder.NoMatch("near miss 1", `bitbar = "VCB3GqFMcB3Id4lTUaz6WjxSh8Gdybv"`),
	},
})
