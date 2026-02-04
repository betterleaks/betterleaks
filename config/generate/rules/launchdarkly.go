package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func LaunchDarklyAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "launchdarkly-access-token",
		Description: "Uncovered a Launchdarkly Access Token, potentially compromising feature flag management and application functionality.",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"launchdarkly"}, utils2.AlphaNumericExtended("40"), true),

		Keywords: []string{
			"launchdarkly",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("launchdarkly", secrets.NewSecret(utils2.AlphaNumericExtended("40")))
	return utils2.Validate(r, tps, nil)
}
