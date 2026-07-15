package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
)

func BitriseAccessToken() *config.Rule {
	r := config.Rule{
		RuleID:      "bitrise-access-token",
		Description: "Detected a Bitrise personal or workspace access token, which may expose CI/CD applications and builds.",
		Regex: utils.GenerateSemiGenericRegex(
			[]string{`bitrise(?:[ _-]*(?:personal|workspace))?(?:[ _-]*(?:access|api))?[ _-]*token`},
			`[A-Za-z0-9_-]{60,120}`,
			false,
		),
		Keywords: []string{"bitrise"},
		ValidateExpr: `let r = http.get("https://api.bitrise.io/v0.1/apps", {
    "Authorization": finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.5),
	}

	return utils.Validate(r,
		[]string{
			`BITRISE_TOKEN=R7mQ2vN9xK4pT8cW1zL6gH3sD5fJ0aB7nM2qV9xK4pT8cW1zL6gH3sD5fJ0aB7`,
			`bitrise workspace api token: Q9xK4pT8cW1zL6gH3sD5fJ0aB7nM2qV9xK4pT8cW1zL6gH3sD5fJ0aB7nM2qV`,
		},
		[]string{
			`TOKEN=R7mQ2vN9xK4pT8cW1zL6gH3sD5fJ0aB7nM2qV9xK4pT8cW1zL6gH3sD5fJ0aB7`,
			`BITRISE_TOKEN=too_short`,
		},
	)
}
