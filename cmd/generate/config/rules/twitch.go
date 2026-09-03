package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

func TwitchAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "twitch-api-token",
		Confidence:  "medium",
		Description: "Discovered a Twitch API token, which could compromise streaming services and account integrations.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"twitch"}, utils.AlphaNumeric("30"), true),
		Keywords: []string{
			"twitch",
		},
		Filter: `filter.entropy(finding["secret"]) < 3.5 || filter.tokenRatio(finding["secret"]) >= 2.5`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("twitch", secrets.NewSecretWithEntropy(utils.AlphaNumeric("30"), 3.5))
	return utils.Validate(r, tps, nil)
}
