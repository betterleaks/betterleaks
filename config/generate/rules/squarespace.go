package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func SquareSpaceAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "squarespace-access-token",
		Description: "Identified a Squarespace Access Token, which may compromise website management and content control on Squarespace.",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"squarespace"}, utils2.Hex8_4_4_4_12(), true),

		Keywords: []string{
			"squarespace",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("squarespace", secrets.NewSecret(utils2.Hex8_4_4_4_12()))
	return utils2.Validate(r, tps, nil)
}
