package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func TwitchAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "twitch-api-token",
		Description: "Discovered a Twitch API token, which could compromise streaming services and account integrations.",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"twitch"}, utils2.AlphaNumeric("30"), true),
		Keywords: []string{
			"twitch",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("twitch", secrets.NewSecret(utils2.AlphaNumeric("30")))
	return utils2.Validate(r, tps, nil)
}
