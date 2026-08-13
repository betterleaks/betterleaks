package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func LaunchDarklyAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "launchdarkly-access-token",
		Confidence:  "high",
		Description: "Uncovered a Launchdarkly Access Token, potentially compromising feature flag management and application functionality.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"launchdarkly"}, utils.AlphaNumericExtended("40"), true),

		Keywords: []string{
			"launchdarkly",
		},
		Filter: `filter.entropy(finding["secret"]) < 3.5`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("launchdarkly", secrets.NewSecretWithEntropy(utils.AlphaNumericExtended("40"), 3.5))
	return utils.Validate(r, tps, nil)
}
