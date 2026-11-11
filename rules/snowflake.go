package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "snowflake-account-host.1",
	Confidence:  "high",
	Description: "Snowflake account host, used as a component of the programmatic access-token rule.",
	Regex:       `(?i)\b([a-z0-9_-]+(?:\.[a-z0-9_-]+)*\.snowflakecomputing\.com)\b`,
	Keywords:    []string{"snowflakecomputing.com"},
	SkipReport:  true,
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Mode:  "match",
			Input: "SNOWFLAKE_HOST=xy12345.us-east-1.snowflakecomputing.com",
			Expect: []config.ExpectedFinding{
				{Secret: "xy12345.us-east-1.snowflakecomputing.com"},
			},
		},
		{
			Name:  "true positive 2",
			Mode:  "match",
			Input: "host=acme-prod.eu-west-1.aws.snowflakecomputing.com",
			Expect: []config.ExpectedFinding{
				{Secret: "acme-prod.eu-west-1.aws.snowflakecomputing.com"},
			},
		},
		{
			Name:   "false positive 1",
			Mode:   "match",
			Input:  "SNOWFLAKE_HOST=xy12345.example.com",
			Expect: []config.ExpectedFinding{},
		},
		{
			Name:   "false positive 2",
			Mode:   "match",
			Input:  "SNOWFLAKE_HOST=snowflakecomputing.com.evil.example",
			Expect: []config.ExpectedFinding{},
		},
	},
})

var _ = Add(config.Rule{
	ID:          "snowflake-programmatic-access-token.1",
	Confidence:  "high",
	Description: "Snowflake programmatic access token.",
	Regex: Assignment(
		[]string{`(?:snowflake[_. -]*(?:programmatic[_. -]*)?(?:access[_. -]*)?token|sf[_. -]*token)`},
		`[A-Za-z0-9_-]{100,500}`,
	),
	Keywords: []string{"snowflake", "sf_token"},
	Components: []config.Component{
		{RuleID: "snowflake-account-host.1", Within: "30L"},
	},
	ValidateExpr: `let r = http.post("https://" + (components["snowflake-account-host.1"]?.secret ?? "") + "/api/v2/statements", {
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
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Input: "SNOWFLAKE_TOKEN=WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG7ubf2TxReZd1UXAceqba86woUt0S8fdI2myN1nZ6NYCy0bQx6umpyk9dz5c02tMq\nSNOWFLAKE_HOST=xy12345.us-east-1.snowflakecomputing.com",
			Expect: []config.ExpectedFinding{
				{Secret: "WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG7ubf2TxReZd1UXAceqba86woUt0S8fdI2myN1nZ6NYCy0bQx6umpyk9dz5c02tMq", ComponentSets: []map[string]string{{"snowflake-account-host.1": "xy12345.us-east-1.snowflakecomputing.com"}}},
			},
		},
		NoMatch("false positive 1", "SNOWFLAKE_TOKEN=short"),
		NoMatch("false positive 2", "ACCESS_TOKEN=AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCdEfGhIjKlMnOpQrStUvWxYz12"),
	},
})
