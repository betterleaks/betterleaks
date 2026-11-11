package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "neon-api-key",
	Confidence:  "high",
	Description: "Neon API key.",
	Regex:       Token(`napi_[A-Za-z0-9]{64}`),
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
	FilterExpr: MinEntropy(3.5),
	Tests: []config.RuleTest{
		Match("true positive 1", "NEON_API_KEY=napi_5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7nz6lc", "napi_5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7nz6lc"),
		NoMatch("false positive 1", "NEON_API_KEY=napi_short"),
		NoMatch("false positive 2", "NEON_API_KEY=napi_0000000000000000000000000000000000000000000000000000000000000000"),
	},
})

// NeonConnectionURI is not registered in the default config.
// TODO: Register it once Betterleaks has a PostgreSQL validator.
func NeonConnectionURI() config.Rule {
	return config.Rule{
		ID:          "neon-connection-uri",
		Confidence:  "high",
		Description: "Password embedded in a Neon PostgreSQL connection URI.",
		Regex:       `\bpostgres(?:ql)?://[^:@\s]{1,64}:([^@\s]{6,128})@[^\s/"']{4,200}\.neon\.tech\b`,
		Keywords:    []string{".neon.tech"},
		FilterExpr:  MinEntropy(2.5),
		Tests: []config.RuleTest{
			Match("true positive 1", "DATABASE_URL=postgresql://app:RFbD56TI2smTyVsGd5Xa@ep-cool-darkness-a1b2c3.us-east-2.aws.neon.tech/neondb?sslmode=require", "RFbD56TI2smTyVsGd5Xa"),
			NoMatch("false positive 1", "DATABASE_URL=postgresql://app@ep-cool-darkness-a1b2c3.us-east-2.aws.neon.tech/neondb"),
			NoMatch("false positive 2", "DATABASE_URL=postgresql://app:password@postgres.example.com/neondb"),
		},
	}
}
