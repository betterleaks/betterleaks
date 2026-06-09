package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func InfluxDBAPIToken() *config.Rule {
	r := config.Rule{
		RuleID:      "influxdb-api-token",
		Description: "Detected an InfluxDB API token, which may allow unauthorized access to time-series data and InfluxDB organization resources.",
		Regex:       regexp.MustCompile(`(?i)(?:\binflux(?:db)?\b(?:.|[\n\r]){0,64}?\b(?:token|api[_-]?key)\b(?:.|[\n\r]){0,32}?)[=:"'\s]{1,8}([A-Za-z0-9+/=_-]{88,})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`),
		Keywords:    []string{"influx"},
		ValidateCEL: `cel.bind(r,
  http.get("https://us-east-1-1.aws.cloud2.influxdata.com/api/v2/orgs", {
    "Authorization": "Token " + finding["secret"],
    "Accept": "application/json"
  }),
  r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)
)`,
		Filter: `filter.entropy(finding["secret"]) < 4.0`,
	}

	tps := []string{
		`influx
token=nxft2SEGZrEH2-jwDIea6tDSiX6TqHn50u0kOcDqSRnUdnK35VYauC1buWdwh-UFq7dgeb7qf3pMyKg6sbf6zg==`,
		`influxdb
token='z62qZYqGCOCI1zx3cFZYFcosWJoGw9XKIeEcF_GWwhfefRBSMjQfl3M5-ZDZN1FOFvWJPJHVi2-bZ6hPaQWvpw=='`,
	}
	fps := []string{
		`influx token=short`,
		`token=nxft2SEGZrEH2-jwDIea6tDSiX6TqHn50u0kOcDqSRnUdnK35VYauC1buWdwh-UFq7dgeb7qf3pMyKg6sbf6zg==`,
	}
	return utils.Validate(r, tps, fps)
}
