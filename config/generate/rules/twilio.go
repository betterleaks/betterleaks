package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
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
	tps := utils2.GenerateSampleSecrets("twilio", "SK"+secrets.NewSecret(utils2.Hex("32")))
	return utils2.Validate(r, tps, nil)
}
