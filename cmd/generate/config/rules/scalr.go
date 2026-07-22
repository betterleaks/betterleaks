package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
)

func ScalrAPIAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "scalr-api-access-token.1",
		Description: "Scalr API access token.",
		Regex: utils.GenerateSemiGenericRegex(
			[]string{`scalr(?:[_. -]*(?:api|access))?[_. -]*(?:secret|key|token)`},
			`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.eyJpc3MiOiJ1c2VyIiwianRpIjoiYXQt[A-Za-z0-9_-]{20,40}\.[A-Za-z0-9_-]{43}`,
			false,
		),
		Keywords: []string{"scalr"},
		ValidateExpr: `let r = http.get("https://scalr.io/api/iacp/v3/accounts", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/vnd.api+json"
  }); r.status == 200 && (r.body contains "\"data\"") ? {
    "result": "valid"
  } : r.status == 403 ? {
    "result": "valid",
    "reason": "Authenticated but account access is restricted"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.5),
	}

	// validate
	tps := []string{
		`SCALR_KEY="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ1c2VyIiwianRpIjoiYXQtdzFwNWtvN2h2ODh0bGVzcDAifQ.VCPHD8dI5RAO4yexSrfk7mhrBu1KFnGU3Rm2zwApplF"`,
	}
	fps := []string{
		`OTHER_JWT="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ1c2VyIiwianRpIjoiYXQtdzFwNWtvN2h2ODh0bGVzcDAifQ.VCPHD8dI5RAO4yexSrfk7mhrBu1KFnGU3Rm2zwApplF"`,
		`SCALR_KEY=eyJhbGciOiJIUzI1NiJ9.short.token`,
	}
	return utils.Validate(r, tps, fps)
}
