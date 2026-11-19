package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "instantly-api-key.1",
	Confidence:  "medium",
	Description: "Instantly API key, which may allow access to campaigns, accounts, leads, and analytics.",
	Regex:       rulebuilder.Assignment([]string{"instantly"}, `[A-Za-z0-9+/]{66}==`),
	Keywords:    []string{"instantly"},
	ValidateExpr: `let r = http.get("https://api.instantly.ai/api/v2/accounts?limit=1", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status == 402 ? {
    "result": "valid",
    "reason": "Authenticated but the workspace does not have an active paid plan"
  } : r.status == 401 && (r.body contains "Invalid authorization header or API key") ? {
    "result": "invalid",
    "reason": "Invalid API key"
  } : validate.unknown(r)`,
	FilterExpr: rulebuilder.MinEntropy(3.3),
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "INSTANTLY_API_KEY=VD5v/4tg6Y4jWlMO9JZWDOcGzfjsqrpsPDZAdrxGBG81lHSYzNJ7pLcF6ubf1SxQeY==", "VD5v/4tg6Y4jWlMO9JZWDOcGzfjsqrpsPDZAdrxGBG81lHSYzNJ7pLcF6ubf1SxQeY=="),
		rulebuilder.Match("true positive 2", `instantly.ai token: "VD5v/4tg6Y4jWlMO9JZWDOcGzfjsqrpsPDZAdrxGBG81lHSYzNJ7pLcF6ubf1SxQeY=="`, "VD5v/4tg6Y4jWlMO9JZWDOcGzfjsqrpsPDZAdrxGBG81lHSYzNJ7pLcF6ubf1SxQeY=="),
		rulebuilder.NoMatch("false positive 1", "API_KEY=VD5v/4tg6Y4jWlMO9JZWDOcGzfjsqrpsPDZAdrxGBG81lHSYzNJ7pLcF6ubf1SxQeY=="),
		rulebuilder.NoMatch("false positive 2", "INSTANTLY_API_KEY=short"),
		rulebuilder.NoMatch("false positive 3", "INSTANTLY_API_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="),
	},
})
