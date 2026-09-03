package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
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
		Filter: `filter.entropy(finding["secret"]) < 3.0 || filter.tokenRatio(finding["secret"]) >= 2.5`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("mattermost", secrets.NewSecretWithEntropy(utils.AlphaNumeric("26"), 3.0))
	return utils.Validate(r, tps, nil)
}
