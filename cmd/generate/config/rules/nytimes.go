package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func NytimesAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "nytimes-access-token",
		Confidence:  "high",
		Description: "Detected a Nytimes Access Token, risking unauthorized access to New York Times APIs and content services.",
		Regex: utils.GenerateSemiGenericRegex([]string{
			"nytimes", "new-york-times", "newyorktimes"},
			utils.AlphaNumericExtended("32"), true),

		Keywords: []string{
			"nytimes",
			"new-york-times",
			"newyorktimes",
		},
		Filter: `filter.entropy(finding["secret"]) < 3.5 || filter.tokenRatio(finding["secret"]) >= 2.5`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("nytimes", secrets.NewSecretWithEntropy(utils.AlphaNumeric("32"), 3.5))
	return utils.Validate(r, tps, nil)
}
