package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func SendInBlueAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "sendinblue-api-token",
		Description: "Identified a Sendinblue API token, which may compromise email marketing services and subscriber data privacy.",
		Regex:       utils.GenerateUniqueTokenRegex(`xkeysib-[a-f0-9]{64}\-(?i)[a-z0-9]{16}`, false),
		Entropy:     2,
		Keywords: []string{
			"xkeysib-",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("sendinblue", "xkeysib-"+secrets.NewSecretWithEntropy(utils.Hex("64"), 2)+"-"+secrets.NewSecretWithEntropy(utils.AlphaNumeric("16"), 2))
	return utils.Validate(r, tps, nil)
}
