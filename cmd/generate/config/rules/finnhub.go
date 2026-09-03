package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
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
		Filter: `filter.entropy(finding["secret"]) < 3.0 || filter.tokenRatio(finding["secret"]) >= 2.5`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("finnhub", secrets.NewSecretWithEntropy(utils.AlphaNumeric("20"), 3.0))
	return utils.Validate(r, tps, nil)
}
