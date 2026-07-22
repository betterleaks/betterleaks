package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
)

func WorkOSProductionAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "workos-production-api-key.1",
		Description: "WorkOS production API key.",
		Regex: utils.GenerateSemiGenericRegex(
			[]string{`workos(?:[_. -]*(?:api))?[_. -]*(?:secret|key|token)`},
			`sk_live_a2V5Xz[A-Za-z0-9+/]{69}={0,2}`,
			false,
		),
		Keywords: []string{"workos"},
		ValidateExpr: `let r = http.get("https://api.workos.com/organizations", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 && (r.body contains "\"data\"") ? {
    "result": "valid"
  } : r.status == 403 ? {
    "result": "valid",
    "reason": "Authenticated but organization access is restricted"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
		Filter: `filter.entropy(finding["secret"]) < 3.5
|| filter.matchesAny(finding["secret"], ["(?i)example"])`,
	}

	// validate
	tps := []string{
		`WORKOS_API_KEY=sk_live_a2V5XzAxS1BSWE1LTjBEWE1INlpBU0VEWjU2VFE3LFdjOWxFMTNDS29xRkdlYU9uMUpDbUpTZWE`,
	}
	fps := []string{
		`STRIPE_SECRET_KEY=sk_live_a2V5XzAxS1BSWE1LTjBEWE1INlpBU0VEWjU2VFE3LFdjOWxFMTNDS29xRkdlYU9uMUpDbUpTZWE`,
		`WORKOS_API_KEY=sk_test_example`,
		`WORKOS_API_KEY=sk_live_a2V5Xzexampleexampleexampleexampleexampleexampleexampleexampleexampleexample`,
	}
	return utils.Validate(r, tps, fps)
}
