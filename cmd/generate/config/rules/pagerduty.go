package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

func PagerDutyAuthorizationToken() *config.Rule {
	r := config.Rule{
		RuleID:      "pagerduty-authorization-token.1",
		Confidence:  "high",
		Description: "PagerDuty authorization token, which may allow access to PagerDuty account and incident data.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"pagerduty"}, `u\+[A-Za-z0-9_+-]{18}`, false),
		Keywords:    []string{"pagerduty"},
		ValidateExpr: `let r = http.get("https://api.pagerduty.com/users?limit=1", {
    "Authorization": "Token token=" + finding["secret"],
    "Accept": "application/vnd.pagerduty+json;version=2"
  }); r.status == 200 && (r.body contains "\"users\"") ? {
    "result": "valid"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.5),
	}

	token := "u+" + secrets.NewSecretWithEntropy(`[A-Za-z0-9_+-]{18}`, 3.5)
	tps := []string{
		`PAGERDUTY_API_TOKEN=` + token,
		`pagerduty authorization: "` + token + `"`,
	}
	fps := []string{
		`API_TOKEN=` + token,
		`PAGERDUTY_API_TOKEN=u+short`,
		`PAGERDUTY_API_TOKEN=u+000000000000000000`,
	}
	return utils.Validate(r, tps, fps)
}
