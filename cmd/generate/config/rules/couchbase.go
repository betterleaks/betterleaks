package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func CouchbaseCapellaAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "couchbase-capella-api-key",
		Description: "Detected a Couchbase Capella API key secret, which may allow unauthorized access to Couchbase Capella management APIs.",
		Regex:       regexp.MustCompile(`(?i)\b(?:couchbase|capella)(?:.|[\n\r]){0,32}?(?:api(?:.|[\n\r]){0,12}?(?:key|secret)|key(?:.|[\n\r]){0,12}?secret)(?:.|[\n\r]){0,32}?\b([A-Za-z0-9+/]{60,120}={0,2})\b`),
		Keywords:    []string{"couchbase", "capella"},
		ValidateCEL: `cel.bind(r,
  http.get("https://cloudapi.cloud.couchbase.com/v4/organizations", {
    "Accept": "application/json",
    "Authorization": "Bearer " + finding["secret"]
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
		`COUCHBASE_API_KEY_SECRET="QktxVUtFU1dKV1FlJBYXdnTVlRemFZdmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MDJBQ0RF"`,
		`capella_api_secret = 'aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ3aA4bB5cC6dD7eE8fF9gG0hH1iJ2kL3m=='`,
	}
	fps := []string{
		`api_secret = 'aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ3aA4bB5cC6dD7eE8fF9gG0hH1iJ2kL3m=='`,
		`COUCHBASE_API_KEY_SECRET="short"`,
	}
	return utils.Validate(r, tps, fps)
}
