package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func DatadogtokenAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "datadog-access-token",
		Description: "Detected a Datadog Access Token, potentially risking monitoring and analytics data exposure and manipulation.",
		Regex: utils.GenerateSemiGenericRegex([]string{"datadog"},
			utils.AlphaNumeric("40"), true),
		Keywords: []string{
			"datadog",
		},
		ValidateCEL: `cel.bind(r,
  http.get("https://api.datadoghq.com/api/v1/validate", {
    "DD-API-KEY": finding["secret"]
  }),
  r.status == 200 && r.json.?valid.orValue(false) == true ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("datadog", secrets.NewSecret(utils.AlphaNumeric("40")))
	return utils.Validate(r, tps, nil)
}
