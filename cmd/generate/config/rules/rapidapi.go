package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func RapidAPIAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "rapidapi-access-token",
		Confidence:  "high",
		Description: "Uncovered a RapidAPI Access Token, which could lead to unauthorized access to various APIs and data services.",
		Regex: utils.GenerateSemiGenericRegex([]string{"rapidapi"},
			utils.AlphaNumericExtendedShort("50"), true),

		Keywords: []string{
			"rapidapi",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("rapidapi", secrets.NewSecret(utils.AlphaNumericExtendedShort("50")))
	return utils.Validate(r, tps, nil)
}
