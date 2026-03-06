package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func Dynatrace() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "dynatrace-api-token",
		Description: "Detected a Dynatrace API token, potentially risking application performance monitoring and data exposure.",
		Regex:       regexp.MustCompile(`dt0c01\.(?i)[a-z0-9]{24}\.[a-z0-9]{64}`),
		Entropy:     4,
		Keywords:    []string{"dt0c01."},
	}

	// validate
	tps := utils.GenerateSampleSecrets("dynatrace", "dt0c01."+secrets.NewSecretWithEntropy(utils.AlphaNumeric("24"), 4)+"."+secrets.NewSecretWithEntropy(utils.AlphaNumeric("64"), 4))
	return utils.Validate(r, tps, nil)
}
