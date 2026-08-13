package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func GitterAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "gitter-access-token",
		Confidence:  "high",
		Description: "Uncovered a Gitter Access Token, which may lead to unauthorized access to chat and communication services.",
		Regex: utils.GenerateSemiGenericRegex([]string{"gitter"},
			utils.AlphaNumericExtendedShort("40"), true),

		Keywords: []string{
			"gitter",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("gitter", secrets.NewSecret(utils.AlphaNumericExtendedShort("40")))
	return utils.Validate(r, tps, nil)
}
