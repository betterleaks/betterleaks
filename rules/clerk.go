package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "clerk-secret-key",
	Confidence:  "medium",
	Description: "Detected a Clerk secret key, which may allow unauthorized access to Clerk backend APIs.",
	Regex:       rulebuilder.Assignment([]string{"clerk"}, `(?i)sk_(?:test|live)_[A-Za-z0-9]{32}`),
	Keywords:    []string{"clerk"},
	ValidateExpr: `let r = http.get("https://api.clerk.com/v1/users?limit=1", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) < 3.3`,
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "clerk_secret = sk_test_4pX9kL2mN8qR3sT7vY1zA3bC6dE0fG2h", "sk_test_4pX9kL2mN8qR3sT7vY1zA3bC6dE0fG2h"),
		rulebuilder.Match("true positive 2", "CLERK_SECRET_KEY=sk_live_aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV", "sk_live_aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV"),
		rulebuilder.NoMatch("false positive 1", "CLERK_SECRET_KEY=sk_live_short"),
		rulebuilder.NoMatch("false positive 2", "SECRET_KEY=sk_live_abcdefghijklmnopqrstuvwxyz123456"),
	},
})
