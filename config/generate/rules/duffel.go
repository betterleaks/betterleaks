package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
	"github.com/betterleaks/betterleaks/regexp"
)

func Duffel() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "duffel-api-token",
		Description: "Uncovered a Duffel API token, which may compromise travel platform integrations and sensitive customer data.",
		Regex:       regexp.MustCompile(`duffel_(?:test|live)_(?i)[a-z0-9_\-=]{43}`),
		Entropy:     2,
		Keywords:    []string{"duffel_"},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("duffel", "duffel_test_"+secrets.NewSecret(utils2.AlphaNumericExtended("43")))
	return utils2.Validate(r, tps, nil)
}
