package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func ApolloAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "apollo-api-key.1",
		Confidence:  "medium",
		Description: "Apollo.io API key, which may allow access to sales intelligence and engagement data.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"apollo"}, `[A-Za-z0-9_-]{22}`, false),
		Keywords:    []string{"apollo"},
		ValidateExpr: `let r = http.post("https://api.apollo.io/api/v1/mixed_people/api_search", {
    "X-Api-Key": finding["secret"],
    "Accept": "application/json",
    "Content-Type": "application/json"
  }, "{\"page\":1,\"per_page\":1}"); r.status == 200 && (r.body contains "\"total_entries\"") ? {
    "result": "valid"
  } : r.status == 403 && (r.body contains "API_INACCESSIBLE") ? {
    "result": "valid",
    "reason": "Authenticated but this API is unavailable to the account"
  } : r.status == 401 && (r.body contains "Invalid API key") ? {
    "result": "invalid",
    "reason": "Invalid API key"
  } : validate.unknown(r)`,
		Filter: `filter.entropy(finding["secret"]) < 3.0 || filter.tokenRatio(finding["secret"]) >= 2.5`,
	}

	key := secrets.NewSecretWithEntropy(`[A-Za-z0-9_-]{22}`, 3.0)
	tps := []string{
		`APOLLO_API_KEY=` + key,
		`apollo.io token: "` + key + `"`,
	}
	fps := []string{
		`API_KEY=` + key,
		`APOLLO_API_KEY=abcdefghijklmnopqrstuv`,
		`APOLLO_API_KEY=short`,
	}
	return utils.Validate(r, tps, fps)
}
