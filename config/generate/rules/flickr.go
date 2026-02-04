package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func FlickrAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "flickr-access-token",
		Description: "Discovered a Flickr Access Token, posing a risk of unauthorized photo management and potential data leakage.",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"flickr"}, utils2.AlphaNumeric("32"), true),

		Keywords: []string{
			"flickr",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("flickr", secrets.NewSecret(utils2.AlphaNumeric("32")))
	return utils2.Validate(r, tps, nil)
}
