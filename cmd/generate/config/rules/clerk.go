package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
)

func ClerkSecretKey() *config.Rule {
	r := config.Rule{
		RuleID:      "clerk-secret-key",
		Description: "Detected a Clerk secret key, which may allow unauthorized access to Clerk backend APIs.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"clerk"}, `sk_(?:test|live)_[A-Za-z0-9]{32}`, true),
		Keywords:    []string{"clerk"},
		ValidateCEL: `cel.bind(r,
  http.get("https://api.clerk.com/v1/users?limit=1", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }),
  r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)
)`,
		Filter: `filter.entropy(finding["secret"]) < 3.3`,
	}

	tps := []string{
		`clerk_secret = sk_test_4pX9kL2mN8qR3sT7vY1zA3bC6dE0fG2h`,
		`CLERK_SECRET_KEY=sk_live_aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV`,
	}
	fps := []string{
		`CLERK_SECRET_KEY=sk_live_short`,
		`SECRET_KEY=sk_live_abcdefghijklmnopqrstuvwxyz123456`,
	}
	return utils.Validate(r, tps, fps)
}
