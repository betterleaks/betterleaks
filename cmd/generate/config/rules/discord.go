package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func DiscordAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "discord-api-token",
		Confidence:  "medium",
		Description: "Detected a Discord API key, potentially compromising communication channels and user data privacy on Discord.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"discord"}, utils.Hex("64"), true),
		Keywords:    []string{"discord"},
		Filter:      `filter.entropy(finding["secret"]) < 3.3 || filter.tokenRatio(finding["secret"]) >= 2.5`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("discord", secrets.NewSecretWithEntropy(utils.Hex("64"), 3.3))
	return utils.Validate(r, tps, nil)
}

func DiscordClientID() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "discord-client-id",
		Confidence:  "medium",
		Description: "Identified a Discord client ID, which may lead to unauthorized integrations and data exposure in Discord applications.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"discord"}, utils.Numeric("18"), true),
		Keywords:    []string{"discord"},
		Filter:      `filter.entropy(finding["secret"]) < 2.75`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("discord", secrets.NewSecretWithEntropy(utils.Numeric("18"), 2.75))
	fps := []string{
		// Low entropy
		`discord=000000000000000000`,
	}
	return utils.Validate(r, tps, fps)
}

func DiscordClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "discord-client-secret",
		Confidence:  "medium",
		Description: "Discovered a potential Discord client secret, risking compromised Discord bot integrations and data leaks.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"discord"}, utils.AlphaNumericExtended("32"), true),
		Keywords:    []string{"discord"},
		Filter:      `filter.entropy(finding["secret"]) < 3.5 || filter.tokenRatio(finding["secret"]) >= 2.5`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("discord", secrets.NewSecretWithEntropy(utils.AlphaNumericExtended("32"), 3.5))
	fps := []string{
		// Low entropy
		`discord=00000000000000000000000000000000`,
		// TODO:
		//`discord=01234567890123456789012345678901`,
	}
	return utils.Validate(r, tps, fps)
}
