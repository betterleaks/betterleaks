package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/regexp"
)

func Twilio() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "twilio-api-key",
		Confidence:  "high",
		Description: "Found a Twilio API Key, posing a risk to communication services and sensitive customer interaction data.",
		Regex:       regexp.MustCompile(`SK[0-9a-fA-F]{32}`),
		Keywords:    []string{"twilio"},
		Filter:      `entropy(finding["secret"]) <= 3.0`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("twilio", "SK"+secrets.NewSecretWithEntropy(utils.Hex("32"), 3))
	return utils.Validate(r, tps, nil)
}
