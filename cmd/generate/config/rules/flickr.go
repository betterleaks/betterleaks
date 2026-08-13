package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func FlickrAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "flickr-access-token",
		Confidence:  "high",
		Description: "Discovered a Flickr Access Token, posing a risk of unauthorized photo management and potential data leakage.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"flickr"}, utils.AlphaNumeric("32"), true),

		Keywords: []string{
			"flickr",
		},
		Filter: `filter.entropy(finding["secret"]) < 3.5`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("flickr", secrets.NewSecretWithEntropy(utils.AlphaNumeric("32"), 3.5))
	return utils.Validate(r, tps, nil)
}
