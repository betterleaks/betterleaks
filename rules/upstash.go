package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "upstash-redis-rest-url.1",
	Confidence:  "high",
	Description: "Upstash Redis REST URL, used as a component of the Upstash REST-token composite rule.",
	Regex:       Token(`(?i)https://[a-z0-9][a-z0-9-]{2,63}\.upstash\.io`),
	Keywords:    []string{"upstash.io"},
	SkipReport:  true,
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Mode:  "match",
			Input: "UPSTASH_REDIS_REST_URL=https://steady-cobra-12345.upstash.io",
			Expect: []config.ExpectedFinding{
				{Secret: "https://steady-cobra-12345.upstash.io"},
			},
		},
		{
			Name:   "false positive 1",
			Mode:   "match",
			Input:  "UPSTASH_REDIS_REST_URL=https://example.com",
			Expect: []config.ExpectedFinding{},
		},
		{
			Name:   "false positive 2",
			Mode:   "match",
			Input:  "UPSTASH_REDIS_REST_URL=http://steady-cobra-12345.upstash.io",
			Expect: []config.ExpectedFinding{},
		},
	},
})

// The URL component is restricted to an HTTPS hostname under upstash.io,
// preventing arbitrary-host validation while supporting per-database URLs.
var _ = Add(config.Rule{
	ID:          "upstash-redis-rest-token.1",
	Confidence:  "high",
	Description: "Upstash Redis REST token, which may grant read-only or full access to an Upstash database.",
	Regex: Assignment(
		[]string{"upstash"},
		`(?:[A-Za-z0-9]{32,48}|AYNgAS[A-Za-z0-9+/_-]{26,90}={0,2})`,
	),
	Keywords: []string{"upstash"},
	Components: []config.Component{
		{RuleID: "upstash-redis-rest-url.1", Within: "5L"},
	},
	ValidateExpr: `let endpoint = (components["upstash-redis-rest-url.1"]?.secret ?? "");
let r = http.get(endpoint + "/ping", {
  "Authorization": "Bearer " + finding["secret"],
  "Accept": "application/json"
}); r.status == 200 && (r.body contains "PONG") ? {
  "result": "valid"
} : r.status == 401 ? {
  "result": "invalid",
  "reason": "Unauthorized"
} : validate.unknown(r)`,
	FilterExpr: MinEntropy(3.5),
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Input: "UPSTASH_REDIS_REST_TOKEN=RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575k\nUPSTASH_REDIS_REST_URL=https://steady-cobra-12345.upstash.io",
			Expect: []config.ExpectedFinding{
				{Secret: "RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575k", ComponentSets: []map[string]string{{"upstash-redis-rest-url.1": "https://steady-cobra-12345.upstash.io"}}},
			},
		},
		{
			Name:  "true positive 2",
			Input: "upstash redis token: \"AYNgASKfnhAi4kP3Npo8Vkl2bZb+T76pjPL6pF2Kxefvfi=\"\nUPSTASH_REDIS_REST_URL=https://steady-cobra-12345.upstash.io",
			Expect: []config.ExpectedFinding{
				{Secret: "AYNgASKfnhAi4kP3Npo8Vkl2bZb+T76pjPL6pF2Kxefvfi=", ComponentSets: []map[string]string{{"upstash-redis-rest-url.1": "https://steady-cobra-12345.upstash.io"}}},
			},
		},
		NoMatch("false positive 1", "REDIS_REST_TOKEN=RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575k"),
		NoMatch("false positive 2", "UPSTASH_REDIS_REST_TOKEN=short"),
		NoMatch("false positive 3", "UPSTASH_REDIS_REST_TOKEN=0000000000000000000000000000000000000000"),
	},
})
