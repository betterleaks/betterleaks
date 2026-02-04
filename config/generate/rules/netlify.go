package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func NetlifyAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "netlify-access-token",
		Description: "Detected a Netlify Access Token, potentially compromising web hosting services and site management.",
		Regex: utils2.GenerateSemiGenericRegex([]string{"netlify"},
			utils2.AlphaNumericExtended("40,46"), true),

		Keywords: []string{
			"netlify",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("netlify", secrets.NewSecret(utils2.AlphaNumericExtended("40,46")))
	return utils2.Validate(r, tps, nil)
}
