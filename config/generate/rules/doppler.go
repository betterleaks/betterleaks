package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
	"github.com/betterleaks/betterleaks/regexp"
)

func Doppler() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "doppler-api-token",
		Description: "Discovered a Doppler API token, posing a risk to environment and secrets management security.",
		Regex:       regexp.MustCompile(`dp\.pt\.(?i)[a-z0-9]{43}`),
		Entropy:     2,
		Keywords:    []string{`dp.pt.`},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("doppler", "dp.pt."+secrets.NewSecret(utils2.AlphaNumeric("43")))
	return utils2.Validate(r, tps, nil)
}

// TODO add additional doppler formats:
// https://docs.doppler.com/reference/auth-token-formats
