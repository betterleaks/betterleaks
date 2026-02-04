package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
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
	tps := utils2.GenerateSampleSecrets("dynatrace", "dt0c01."+secrets.NewSecret(utils2.AlphaNumeric("24"))+"."+secrets.NewSecret(utils2.AlphaNumeric("64")))
	return utils2.Validate(r, tps, nil)
}
