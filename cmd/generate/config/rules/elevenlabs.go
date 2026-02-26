package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func ElevenLabs() *config.Rule {
	r := config.Rule{
		RuleID:      "elevenlabs-api-key",
		Description: "Detected an ElevenLabs API Key, which may expose AI voice synthesis services to unauthorized access.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"elevenlabs"}, `sk_[0-9a-f]{48}`, true),
		Keywords:    []string{"elevenlabs"},
		Entropy:     3.5,
	}

	tps := utils.GenerateSampleSecrets("elevenlabs", "sk_"+secrets.NewSecret(utils.Hex("48")))
	fps := []string{
		// Too short
		`elevenlabs_key = sk_2a30e5a0d39d5f2c5f6a9d2f95cd0160`,
		// Wrong prefix
		`elevenlabs_key = ak_2a30e5a0d39d5f2c5f6a9d2f95cd016049a6323985479bfd`,
	}
	return utils.Validate(r, tps, fps)
}
