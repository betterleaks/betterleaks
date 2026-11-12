package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "influxdb-api-token",
	Confidence:  "high",
	Description: "Detected an InfluxDB API token, which may allow unauthorized access to time-series data and InfluxDB organization resources.",
	Regex:       `(?i)(?:\binflux(?:db)?\b(?:.|[\n\r]){0,64}?\b(?:token|api[_-]?key)\b(?:.|[\n\r]){0,32}?)[=:"'\s]{1,8}([A-Za-z0-9+/=_-]{88,})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`,
	Keywords:    []string{"influx"},
	ValidateExpr: `let r = http.get("https://us-east-1-1.aws.cloud2.influxdata.com/api/v2/orgs", {
    "Authorization": "Token " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) < 4.0 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "influx\ntoken=nxft2SEGZrEH2-jwDIea6tDSiX6TqHn50u0kOcDqSRnUdnK35VYauC1buWdwh-UFq7dgeb7qf3pMyKg6sbf6zg==", "nxft2SEGZrEH2-jwDIea6tDSiX6TqHn50u0kOcDqSRnUdnK35VYauC1buWdwh-UFq7dgeb7qf3pMyKg6sbf6zg=="),
		rulebuilder.Match("true positive 2", "influxdb\ntoken='z62qZYqGCOCI1zx3cFZYFcosWJoGw9XKIeEcF_GWwhfefRBSMjQfl3M5-ZDZN1FOFvWJPJHVi2-bZ6hPaQWvpw=='", "z62qZYqGCOCI1zx3cFZYFcosWJoGw9XKIeEcF_GWwhfefRBSMjQfl3M5-ZDZN1FOFvWJPJHVi2-bZ6hPaQWvpw=="),
		rulebuilder.NoMatch("false positive 1", "influx token=short"),
		rulebuilder.NoMatch("false positive 2", "token=nxft2SEGZrEH2-jwDIea6tDSiX6TqHn50u0kOcDqSRnUdnK35VYauC1buWdwh-UFq7dgeb7qf3pMyKg6sbf6zg=="),
	},
})
