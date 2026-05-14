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
		Description: "Detected a Nytimes Access Token, risking unauthorized access to New York Times APIs and content services.",
		Regex: utils.GenerateSemiGenericRegex([]string{
			"nytimes", "new-york-times", "newyorktimes"},
			utils.AlphaNumericExtended("32"), true),

		Keywords: []string{
			"nytimes",
			"new-york-times",
			"newyorktimes",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("nytimes", secrets.NewSecret(utils.AlphaNumeric("32")))
	return utils.Validate(r, tps, nil)
}
