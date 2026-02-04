package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func TrelloAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "trello-access-token",
		Description: "Trello Access Token",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"trello"}, `[a-zA-Z-0-9]{32}`, true),

		Keywords: []string{
			"trello",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("trello", secrets.NewSecret(`[a-zA-Z-0-9]{32}`))
	return utils2.Validate(r, tps, nil)
}
