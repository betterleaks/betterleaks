package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func Typeform() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "typeform-api-token",
		Description: "Uncovered a Typeform API token, which could lead to unauthorized survey management and data collection.",
		Regex: utils2.GenerateSemiGenericRegex([]string{"typeform"},
			`tfp_[a-z0-9\-_\.=]{59}`, true),
		Keywords: []string{
			"tfp_",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("typeformAPIToken", "tfp_"+secrets.NewSecret(utils2.AlphaNumericExtended("59")))
	return utils2.Validate(r, tps, nil)
}
