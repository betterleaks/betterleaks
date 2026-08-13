package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func FinnhubAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "finnhub-access-token",
		Confidence:  "high",
		Description: "Found a Finnhub Access Token, risking unauthorized access to financial market data and analytics.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"finnhub"}, utils.AlphaNumeric("20"), true),

		Keywords: []string{
			"finnhub",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("finnhub", secrets.NewSecret(utils.AlphaNumeric("20")))
	return utils.Validate(r, tps, nil)
}
