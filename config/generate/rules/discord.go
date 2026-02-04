package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func DiscordAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "discord-api-token",
		Description: "Detected a Discord API key, potentially compromising communication channels and user data privacy on Discord.",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"discord"}, utils2.Hex("64"), true),
		Keywords:    []string{"discord"},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("discord", secrets.NewSecret(utils2.Hex("64")))
	return utils2.Validate(r, tps, nil)
}

func DiscordClientID() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "discord-client-id",
		Description: "Identified a Discord client ID, which may lead to unauthorized integrations and data exposure in Discord applications.",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"discord"}, utils2.Numeric("18"), true),
		Entropy:     2,
		Keywords:    []string{"discord"},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("discord", secrets.NewSecret(utils2.Numeric("18")))
	fps := []string{
		// Low entropy
		`discord=000000000000000000`,
	}
	return utils2.Validate(r, tps, fps)
}

func DiscordClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "discord-client-secret",
		Description: "Discovered a potential Discord client secret, risking compromised Discord bot integrations and data leaks.",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"discord"}, utils2.AlphaNumericExtended("32"), true),
		Entropy:     2,
		Keywords:    []string{"discord"},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("discord", secrets.NewSecret(utils2.Numeric("32")))
	fps := []string{
		// Low entropy
		`discord=00000000000000000000000000000000`,
		// TODO:
		//`discord=01234567890123456789012345678901`,
	}
	return utils2.Validate(r, tps, fps)
}
