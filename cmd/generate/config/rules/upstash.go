package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

func UpstashRedisRESTURL() *config.Rule {
	r := config.Rule{
		RuleID:      "upstash-redis-rest-url.1",
		Confidence:  "high",
		Description: "Upstash Redis REST URL, used as a component of the Upstash REST-token composite rule.",
		Regex:       utils.GenerateUniqueTokenRegex(`https://[a-z0-9][a-z0-9-]{2,63}\.upstash\.io`, true),
		Keywords:    []string{"upstash.io"},
		SkipReport:  true,
	}

	tps := []string{
		`UPSTASH_REDIS_REST_URL=https://steady-cobra-12345.upstash.io`,
	}
	fps := []string{
		`UPSTASH_REDIS_REST_URL=https://example.com`,
		`UPSTASH_REDIS_REST_URL=http://steady-cobra-12345.upstash.io`,
	}
	return utils.Validate(r, tps, fps)
}

func UpstashRedisRESTToken() *config.Rule {
	// The URL component is restricted to an HTTPS hostname under upstash.io,
	// preventing arbitrary-host validation while supporting per-database URLs.
	r := config.Rule{
		RuleID:      "upstash-redis-rest-token.1",
		Confidence:  "high",
		Description: "Upstash Redis REST token, which may grant read-only or full access to an Upstash database.",
		Regex: utils.GenerateSemiGenericRegex(
			[]string{"upstash"},
			`(?:[A-Za-z0-9]{32,48}|AYNgAS[A-Za-z0-9+/_-]{26,90}={0,2})`,
			false,
		),
		Keywords: []string{"upstash"},
		Components: []*config.Component{
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
		Filter: utils.MinEntropy(3.5),
	}

	token := secrets.NewSecretWithEntropy(`[A-Za-z0-9]{40}`, 3.5)
	aclToken := "AYNgAS" + secrets.NewSecretWithEntropy(`[A-Za-z0-9+/_-]{40}`, 3.5) + "="
	tps := []string{
		`UPSTASH_REDIS_REST_TOKEN=` + token,
		`upstash redis token: "` + aclToken + `"`,
	}
	fps := []string{
		`REDIS_REST_TOKEN=` + token,
		`UPSTASH_REDIS_REST_TOKEN=short`,
		`UPSTASH_REDIS_REST_TOKEN=0000000000000000000000000000000000000000`,
	}
	return utils.Validate(r, tps, fps)
}
