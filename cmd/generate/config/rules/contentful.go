package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func Contentful() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discovered a Contentful delivery API token, posing a risk to content management systems and data integrity.",
		RuleID:      "contentful-delivery-api-token",
		Confidence:  "medium",
		Regex: utils.GenerateSemiGenericRegex([]string{"contentful"},
			utils.AlphaNumericExtended("43"), true),
		Keywords: []string{"contentful"},
		Filter:   `filter.entropy(finding["secret"]) < 3.5 || filter.tokenRatio(finding["secret"]) >= 2.5`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("contentful", secrets.NewSecretWithEntropy(utils.AlphaNumeric("43"), 3.5))
	return utils.Validate(r, tps, nil)
}
