package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func AlibabaAccessKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "alibaba-access-key-id",
		Description: "Detected an Alibaba Cloud AccessKey ID, posing a risk of unauthorized cloud resource access and potential data compromise.",
		Regex:       utils.GenerateUniqueTokenRegex(`LTAI(?i)[a-z0-9]{20}`, false),
		Entropy:     2,
		Keywords:    []string{"LTAI"},
	}

	// validate
	tps := []string{
		"alibabaKey := \"LTAI" + secrets.NewSecretWithEntropy(utils.Hex("20"), 2) + "\"",
	}
	return utils.Validate(r, tps, nil)
}

// TODO
func AlibabaSecretKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "alibaba-secret-key",
		Description: "Discovered a potential Alibaba Cloud Secret Key, potentially allowing unauthorized operations and data access within Alibaba Cloud.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"alibaba"}, utils.AlphaNumeric("30"), true),
		Entropy:     2,
		Keywords:    []string{"alibaba"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("alibaba", secrets.NewSecretWithEntropy(utils.AlphaNumeric("30"), 2))
	return utils.Validate(r, tps, nil)
}
