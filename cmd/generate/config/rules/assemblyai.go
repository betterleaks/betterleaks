package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func AssemblyAI() *config.Rule {
	r := config.Rule{
		RuleID:      "assemblyai-api-key",
		Description: "Detected an AssemblyAI API Key, which may expose speech-to-text services and associated audio data to unauthorized access.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"assemblyai"}, utils.AlphaNumeric("32"), true),
		Keywords:    []string{"assemblyai"},
		Entropy:     3.0,
	}

	tps := utils.GenerateSampleSecrets("assemblyai", secrets.NewSecret(utils.AlphaNumeric("32")))
	fps := []string{
		// Too short
		`assemblyai = fa0ed91518b345468f9df757`,
		// All same chars (low entropy)
		`assemblyai = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`,
	}
	return utils.Validate(r, tps, fps)
}
