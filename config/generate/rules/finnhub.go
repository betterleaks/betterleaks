package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func FinnhubAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "finnhub-access-token",
		Description: "Found a Finnhub Access Token, risking unauthorized access to financial market data and analytics.",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"finnhub"}, utils2.AlphaNumeric("20"), true),

		Keywords: []string{
			"finnhub",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("finnhub", secrets.NewSecret(utils2.AlphaNumeric("20")))
	return utils2.Validate(r, tps, nil)
}
