package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
)

func CodecovAccessToken() *config.Rule {
	r := config.Rule{
		RuleID:      "codecov-access-token",
		Description: "Found a pattern resembling a Codecov Access Token, posing a risk of unauthorized access to code coverage reports and sensitive data.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"codecov"}, `[A-Z0-9-]{36}`, true),
		Keywords:    []string{"codecov"},
		ValidateCEL: `cel.bind(r,
  http.get("https://api.codecov.io/api/v2/github/", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }),
  r.status == 200 && r.body.contains("\"count\":") ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)
)`,
		Filter: `filter.entropy(finding["secret"]) < 3.5`,
	}

	tps := []string{
		`codecov_token = 52acf265-3fc6-4ecd-304a-15940bd04653`,
	}
	fps := []string{
		`codecov_token = short`,
		`token = 52acf265-3fc6-4ecd-304a-15940bd04653`,
	}
	return utils.Validate(r, tps, fps)
}
