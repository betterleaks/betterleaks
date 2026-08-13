package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func MattermostAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "mattermost-access-token",
		Confidence:  "medium",
		Description: "Identified a Mattermost Access Token, which may compromise team communication channels and data privacy.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"mattermost"}, utils.AlphaNumeric("26"), true),

		Keywords: []string{
			"mattermost",
		},
		Filter: `filter.entropy(finding["secret"]) < 3.0`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("mattermost", secrets.NewSecretWithEntropy(utils.AlphaNumeric("26"), 3.0))
	return utils.Validate(r, tps, nil)
}
