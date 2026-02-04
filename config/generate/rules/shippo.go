package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func ShippoAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "shippo-api-token",
		Description: "Discovered a Shippo API token, potentially compromising shipping services and customer order data.",
		Regex:       utils2.GenerateUniqueTokenRegex(`shippo_(?:live|test)_[a-fA-F0-9]{40}`, false),
		Entropy:     2,
		Keywords: []string{
			"shippo_",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("shippo", "shippo_live_"+secrets.NewSecret(utils2.Hex("40")))
	tps = append(tps, utils2.GenerateSampleSecrets("shippo", "shippo_test_"+secrets.NewSecret(utils2.Hex("40")))...)
	return utils2.Validate(r, tps, nil)
}
