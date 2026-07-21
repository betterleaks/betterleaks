package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func NeonAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "neon-api-key",
		Description: "Neon API key.",
		Regex:       utils.GenerateUniqueTokenRegex(`napi_[A-Za-z0-9]{64}`, false),
		Keywords:    []string{"napi_"},
		ValidateExpr: `let r = http.get("https://console.neon.tech/api/v2/projects", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 || (r.status == 400
    && (r.json?.message ?? "") == "org_id is required, you can find it on your organization settings page") ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.5),
	}

	// validate
	tps := []string{
		"NEON_API_KEY=napi_" + secrets.NewSecretWithEntropy(utils.AlphaNumeric("64"), 3.5),
	}
	fps := []string{
		`NEON_API_KEY=napi_short`,
		`NEON_API_KEY=napi_0000000000000000000000000000000000000000000000000000000000000000`,
	}
	return utils.Validate(r, tps, fps)
}

func NeonConnectionURI() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "neon-connection-uri",
		Description: "Password embedded in a Neon PostgreSQL connection URI.",
		Regex:       regexp.MustCompile(`\bpostgres(?:ql)?://[^:@\s]{1,64}:([^@\s]{6,128})@[^\s/"']{4,200}\.neon\.tech\b`),
		Keywords:    []string{".neon.tech"},
		Filter:      utils.MinEntropy(2.5),
	}

	// validate
	tps := []string{
		"DATABASE_URL=postgresql://app:" + secrets.NewSecretWithEntropy(`[A-Za-z0-9]{20}`, 2.5) + "@ep-cool-darkness-a1b2c3.us-east-2.aws.neon.tech/neondb?sslmode=require",
	}
	fps := []string{
		`DATABASE_URL=postgresql://app@ep-cool-darkness-a1b2c3.us-east-2.aws.neon.tech/neondb`,
		`DATABASE_URL=postgresql://app:password@postgres.example.com/neondb`,
	}
	return utils.Validate(r, tps, fps)
}
