package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func DatadogtokenAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "datadog-access-token",
		Description: "Detected a Datadog Access Token, potentially risking monitoring and analytics data exposure and manipulation.",
		Regex: utils2.GenerateSemiGenericRegex([]string{"datadog"},
			utils2.AlphaNumeric("40"), true),
		Keywords: []string{
			"datadog",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("datadog", secrets.NewSecret(utils2.AlphaNumeric("40")))
	return utils2.Validate(r, tps, nil)
}
