package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func HackClubAIAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "hackclub-ai-api-key",
		Description: "Hack Club AI API key.",
		Regex:       regexp.MustCompile(`\b(sk-hc-v1-[a-f0-9]{64})`),
		Keywords:    []string{"sk-hc-v1-"},
		Filter:      utils.MinEntropy(3.5),
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("hackclub", "sk-hc-v1-"+secrets.NewSecretWithEntropy(utils.Hex("64"), 3.5)),
	}
	fps := []string{
		`sk-hc-v1-short`,
	}
	return utils.Validate(r, tps, fps)
}
