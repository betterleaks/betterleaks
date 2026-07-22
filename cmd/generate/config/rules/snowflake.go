package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func SnowflakeAccountHost() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "snowflake-account-host.1",
		Description: "Snowflake account host, used as a component of the programmatic access-token rule.",
		Regex:       regexp.MustCompile(`(?i)\b([a-z0-9_-]+(?:\.[a-z0-9_-]+)*\.snowflakecomputing\.com)\b`),
		Keywords:    []string{"snowflakecomputing.com"},
		SkipReport:  true,
	}

	// validate
	tps := []string{
		`SNOWFLAKE_HOST=xy12345.us-east-1.snowflakecomputing.com`,
		`host=acme-prod.eu-west-1.aws.snowflakecomputing.com`,
	}
	fps := []string{
		`SNOWFLAKE_HOST=xy12345.example.com`,
		`SNOWFLAKE_HOST=snowflakecomputing.com.evil.example`,
	}
	return utils.Validate(r, tps, fps)
}

func SnowflakeProgrammaticAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "snowflake-programmatic-access-token.1",
		Description: "Snowflake programmatic access token.",
		Regex: utils.GenerateSemiGenericRegex(
			[]string{`(?:snowflake[_. -]*(?:programmatic[_. -]*)?(?:access[_. -]*)?token|sf[_. -]*token)`},
			`[A-Za-z0-9_-]{100,500}`,
			false,
		),
		Keywords: []string{"snowflake", "sf_token"},
		RequiredRules: []*config.Required{
			{RuleID: "snowflake-account-host.1", WithinLines: utils.Ptr(30)},
		},
		ValidateExpr: `let r = http.post("https://" + captures["snowflake-account-host.1"] + "/api/v2/statements", {
    "Authorization": "Bearer " + finding["secret"],
    "X-Snowflake-Authorization-Token-Type": "PROGRAMMATIC_ACCESS_TOKEN",
    "Content-Type": "application/json",
    "Accept": "application/json"
  }, "{\"statement\":\"select 1\",\"timeout\":5}"); r.status in [200, 202]
    && ((r.body contains "\"statementHandle\"") || (r.body contains "\"resultSetMetaData\"")) ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.5),
	}

	// validate
	tps := []string{
		"SNOWFLAKE_TOKEN=" + secrets.NewSecretWithEntropy(`[A-Za-z0-9_-]{120}`, 3.5),
	}
	fps := []string{
		`SNOWFLAKE_TOKEN=short`,
		`ACCESS_TOKEN=AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCdEfGhIjKlMnOpQrStUvWxYz12`,
	}
	return utils.Validate(r, tps, fps)
}
