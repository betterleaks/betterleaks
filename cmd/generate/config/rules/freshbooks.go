package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func FreshbooksAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "freshbooks-access-token",
		Description: "Discovered a Freshbooks Access Token, posing a risk to accounting software access and sensitive financial data exposure.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"freshbooks"}, utils.AlphaNumeric("64"), true),

		Keywords: []string{
			"freshbooks",
		},
		ValidateCEL: utils.BearerGetValidationCEL("https://api.freshbooks.com/auth/api/v1/users/me", "true"),
		Filter:      utils.MinEntropy(3.5),
	}

	// validate
	tps := utils.GenerateSampleSecrets("freshbooks", secrets.NewSecret(utils.AlphaNumeric("64")))
	return utils.Validate(r, tps, nil)
}
