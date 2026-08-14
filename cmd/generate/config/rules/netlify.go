package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func NetlifyAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "netlify-access-token",
		Confidence:  "high",
		Description: "Detected a Netlify Access Token, potentially compromising web hosting services and site management.",
		Regex: utils.GenerateSemiGenericRegex([]string{"netlify"},
			utils.AlphaNumericExtended("40,46"), true),

		Keywords: []string{
			"netlify",
		},
		Filter: `filter.entropy(finding["secret"]) < 3.5 || filter.tokenRatio(finding["secret"]) >= 2.5`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("netlify", secrets.NewSecretWithEntropy(utils.AlphaNumericExtended("40,46"), 3.5))
	return utils.Validate(r, tps, nil)
}
