package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

func Duffel() *config.Rule {
	// define rule
	r := config.Rule{
		ID:          "duffel-api-token",
		Confidence:  "high",
		Description: "Uncovered a Duffel API token, which may compromise travel platform integrations and sensitive customer data.",
		Regex:       `duffel_(?:test|live)_(?i)[a-z0-9_\-=]{43}`,
		Keywords:    []string{"duffel_"},
		Filter:      `entropy(finding["secret"]) <= 2.0`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("duffel", "duffel_test_"+secrets.NewSecretWithEntropy(utils.AlphaNumericExtended("43"), 2))
	return utils.Validate(r, tps, nil)
}
