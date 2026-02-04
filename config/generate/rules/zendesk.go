package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func ZendeskSecretKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "zendesk-secret-key",
		Description: "Detected a Zendesk Secret Key, risking unauthorized access to customer support services and sensitive ticketing data.",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"zendesk"}, utils2.AlphaNumeric("40"), true),
		Keywords: []string{
			"zendesk",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("zendesk", secrets.NewSecret(utils2.AlphaNumeric("40")))
	return utils2.Validate(r, tps, nil)
}
