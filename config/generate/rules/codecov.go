package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func CodecovAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "codecov-access-token",
		Description: "Found a pattern resembling a Codecov Access Token, posing a risk of unauthorized access to code coverage reports and sensitive data.",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"codecov"}, utils2.AlphaNumeric("32"), true),
		Keywords: []string{
			"codecov",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("codecov", secrets.NewSecret(utils2.AlphaNumeric("32")))
	return utils2.Validate(r, tps, nil)
}
