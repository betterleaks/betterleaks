package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

func Intercom() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Identified an Intercom API Token, which could compromise customer communication channels and data privacy.",
		RuleID:      "intercom-api-key",
		Confidence:  "medium",
		Regex:       utils.GenerateSemiGenericRegex([]string{"intercom"}, utils.AlphaNumericExtended("60"), true),

		Keywords: []string{"intercom"},
		Filter:   `filter.entropy(finding["secret"]) < 3.5 || filter.tokenRatio(finding["secret"]) >= 2.5`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("intercom", secrets.NewSecretWithEntropy(utils.AlphaNumericExtended("60"), 3.5))
	return utils.Validate(r, tps, nil)
}
