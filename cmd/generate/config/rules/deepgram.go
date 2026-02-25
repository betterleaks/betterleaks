package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func Deepgram() *config.Rule {
	r := config.Rule{
		RuleID:      "deepgram-api-key",
		Description: "Detected a Deepgram API Key, which may expose speech recognition services and audio data to unauthorized access.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"deepgram"}, utils.Hex("40"), true),
		Keywords:    []string{"deepgram"},
		Entropy:     3.5,
	}

	tps := utils.GenerateSampleSecrets("deepgram", secrets.NewSecret(utils.Hex("40")))
	fps := []string{
		// Too short
		`deepgram_key = 948c19ecde2818a1a357fffb14d2fc2a`,
		// All zeros (low entropy)
		`deepgram_key = 0000000000000000000000000000000000000000`,
	}
	return utils.Validate(r, tps, fps)
}
