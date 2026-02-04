package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func NytimesAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "nytimes-access-token",
		Description: "Detected a Nytimes Access Token, risking unauthorized access to New York Times APIs and content services.",
		Regex: utils2.GenerateSemiGenericRegex([]string{
			"nytimes", "new-york-times,", "newyorktimes"},
			utils2.AlphaNumericExtended("32"), true),

		Keywords: []string{
			"nytimes",
			"new-york-times",
			"newyorktimes",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("nytimes", secrets.NewSecret(utils2.AlphaNumeric("32")))
	return utils2.Validate(r, tps, nil)
}
