package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func Contentful() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discovered a Contentful delivery API token, posing a risk to content management systems and data integrity.",
		RuleID:      "contentful-delivery-api-token",
		Regex: utils2.GenerateSemiGenericRegex([]string{"contentful"},
			utils2.AlphaNumericExtended("43"), true),
		Keywords: []string{"contentful"},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("contentful", secrets.NewSecret(utils2.AlphaNumeric("43")))
	return utils2.Validate(r, tps, nil)
}
