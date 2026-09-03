package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

func Deepgram() *config.Rule {
	r := config.Rule{
		RuleID:      "deepgram-api-key",
		Confidence:  "high",
		Description: "Detected a Deepgram API Key, which may expose speech recognition services and audio data to unauthorized access.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"deepgram"}, utils.Hex("40"), true),
		Keywords:    []string{"deepgram"},
		Filter:      `filter.entropy(finding["secret"]) < 3.3 || filter.tokenRatio(finding["secret"]) >= 2.5`,
	}

	tps := utils.GenerateSampleSecrets("deepgram", secrets.NewSecretWithEntropy(utils.Hex("40"), 3.3))
	fps := []string{
		// Too short
		`deepgram_key = 948c19ecde2818a1a357fffb14d2fc2a`,
		// All zeros (low entropy)
		`deepgram_key = 0000000000000000000000000000000000000000`,
	}
	return utils.Validate(r, tps, fps)
}
