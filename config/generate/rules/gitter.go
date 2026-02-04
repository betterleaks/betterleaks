package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func GitterAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "gitter-access-token",
		Description: "Uncovered a Gitter Access Token, which may lead to unauthorized access to chat and communication services.",
		Regex: utils2.GenerateSemiGenericRegex([]string{"gitter"},
			utils2.AlphaNumericExtendedShort("40"), true),

		Keywords: []string{
			"gitter",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("gitter", secrets.NewSecret(utils2.AlphaNumericExtendedShort("40")))
	return utils2.Validate(r, tps, nil)
}
