package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

func TravisCIAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "travisci-access-token",
		Confidence:  "medium",
		Description: "Identified a Travis CI Access Token, potentially compromising continuous integration services and codebase security.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"travis"}, utils.AlphaNumeric("22"), true),

		Keywords: []string{
			"travis",
		},
		Filter: `filter.entropy(finding["secret"]) < 3.0 || filter.tokenRatio(finding["secret"]) >= 2.5`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("travis", secrets.NewSecretWithEntropy(utils.AlphaNumeric("22"), 3.0))
	return utils.Validate(r, tps, nil)
}
