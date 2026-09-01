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

func ContentfulPersonalAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description:  "Discovered a Contentful personal access token, posing a risk to content management systems and data integrity.",
		RuleID:       "contentful-personal-access-token",
		Confidence:   "high",
		Regex:        utils.GenerateUniqueTokenRegex(`CFPAT-[a-zA-Z0-9_\-]{43}`, false),
		Keywords:     []string{"CFPAT-"},
		ValidateExpr: utils.BearerGetValidationExpr("https://api.contentful.com/organizations", "true"),
		Filter:       `entropy(finding["secret"]) <= 4.0`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("contentful", secrets.NewSecretWithEntropy(`CFPAT-[a-zA-Z0-9_\-]{43}`, 4.0))
	return utils.Validate(r, tps, nil)
}
