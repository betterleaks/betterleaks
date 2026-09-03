package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

func ShippoAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "shippo-api-token",
		Confidence:  "high",
		Description: "Discovered a Shippo API token, potentially compromising shipping services and customer order data.",
		Regex:       utils.GenerateUniqueTokenRegex(`shippo_(?:live|test)_[a-fA-F0-9]{40}`, false),
		Keywords: []string{
			"shippo_",
		},
		Filter: `entropy(finding["secret"]) <= 2.0`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("shippo", "shippo_live_"+secrets.NewSecretWithEntropy(utils.Hex("40"), 2))
	tps = append(tps, utils.GenerateSampleSecrets("shippo", "shippo_test_"+secrets.NewSecretWithEntropy(utils.Hex("40"), 2))...)
	return utils.Validate(r, tps, nil)
}
