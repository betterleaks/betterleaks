package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func Twilio() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "twilio-api-key",
		Description: "Found a Twilio API Key, posing a risk to communication services and sensitive customer interaction data.",
		Regex:       regexp.MustCompile(`SK[0-9a-fA-F]{32}`),
		Entropy:     3,
		Keywords:    []string{"SK"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("twilio", "SK"+secrets.NewSecretWithEntropy(utils.Hex("32"), 3))
	return utils.Validate(r, tps, nil)
}
