package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func RapidAPIAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "rapidapi-access-token",
		Description: "Uncovered a RapidAPI Access Token, which could lead to unauthorized access to various APIs and data services.",
		Regex: utils2.GenerateSemiGenericRegex([]string{"rapidapi"},
			utils2.AlphaNumericExtendedShort("50"), true),

		Keywords: []string{
			"rapidapi",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("rapidapi", secrets.NewSecret(utils2.AlphaNumericExtendedShort("50")))
	return utils2.Validate(r, tps, nil)
}
