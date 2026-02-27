package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func CursorAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "cursor-api-key",
		Description: "Detected a Cursor Integrations API Key, which may expose AI-assisted development services to unauthorized access.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"cursor"}, `key_[0-9a-f]{64}`, true),
		Keywords:    []string{"cursor"},
		Entropy:     3.5,
	}

	tps := utils.GenerateSampleSecrets("cursor", "key_"+secrets.NewSecret(utils.Hex("64")))
	fps := []string{
		// Too short
		`cursor_key = key_8c5a7657fc397e114def1b51dd52041`,
		// Wrong prefix
		`cursor_key = tok_8c5a7657fc397e114def1b51dd520410ad50ece61e30b64261ff369ab275ef29`,
	}
	return utils.Validate(r, tps, fps)
}
