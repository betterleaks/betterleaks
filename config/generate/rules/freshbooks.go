package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func FreshbooksAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "freshbooks-access-token",
		Description: "Discovered a Freshbooks Access Token, posing a risk to accounting software access and sensitive financial data exposure.",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"freshbooks"}, utils2.AlphaNumeric("64"), true),

		Keywords: []string{
			"freshbooks",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("freshbooks", secrets.NewSecret(utils2.AlphaNumeric("64")))
	return utils2.Validate(r, tps, nil)
}
