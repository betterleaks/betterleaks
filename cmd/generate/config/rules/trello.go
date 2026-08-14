package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func TrelloAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "trello-access-token",
		Confidence:  "high",
		Description: "Trello Access Token",
		Regex:       utils.GenerateSemiGenericRegex([]string{"trello"}, `[a-zA-Z-0-9]{32}`, true),

		Keywords: []string{
			"trello",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("trello", secrets.NewSecret(`[a-zA-Z-0-9]{32}`))
	return utils.Validate(r, tps, nil)
}
