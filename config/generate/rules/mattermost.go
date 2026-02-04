package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func MattermostAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "mattermost-access-token",
		Description: "Identified a Mattermost Access Token, which may compromise team communication channels and data privacy.",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"mattermost"}, utils2.AlphaNumeric("26"), true),

		Keywords: []string{
			"mattermost",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("mattermost", secrets.NewSecret(utils2.AlphaNumeric("26")))
	return utils2.Validate(r, tps, nil)
}
