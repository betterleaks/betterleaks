package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func ZendeskSecretKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "zendesk-secret-key",
		Confidence:  "high",
		Description: "Detected a Zendesk Secret Key, risking unauthorized access to customer support services and sensitive ticketing data.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"zendesk"}, utils.AlphaNumeric("40"), true),
		Keywords: []string{
			"zendesk",
		},
		Filter: `filter.entropy(finding["secret"]) < 3.5 || filter.tokenRatio(finding["secret"]) >= 2.5`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("zendesk", secrets.NewSecretWithEntropy(utils.AlphaNumeric("40"), 3.5))
	return utils.Validate(r, tps, nil)
}
