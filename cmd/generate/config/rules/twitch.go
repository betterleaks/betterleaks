package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func TwitchAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "twitch-api-token",
		Confidence:  "high",
		Description: "Discovered a Twitch API token, which could compromise streaming services and account integrations.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"twitch"}, utils.AlphaNumeric("30"), true),
		Keywords: []string{
			"twitch",
		},
		Filter: `filter.entropy(finding["secret"]) < 3.5`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("twitch", secrets.NewSecretWithEntropy(utils.AlphaNumeric("30"), 3.5))
	return utils.Validate(r, tps, nil)
}
