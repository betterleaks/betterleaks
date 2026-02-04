package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func AlibabaAccessKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "alibaba-access-key-id",
		Description: "Detected an Alibaba Cloud AccessKey ID, posing a risk of unauthorized cloud resource access and potential data compromise.",
		Regex:       utils2.GenerateUniqueTokenRegex(`LTAI(?i)[a-z0-9]{20}`, false),
		Entropy:     2,
		Keywords:    []string{"LTAI"},
	}

	// validate
	tps := []string{
		"alibabaKey := \"LTAI" + secrets.NewSecret(utils2.Hex("20")) + "\"",
	}
	return utils2.Validate(r, tps, nil)
}

// TODO
func AlibabaSecretKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "alibaba-secret-key",
		Description: "Discovered a potential Alibaba Cloud Secret Key, potentially allowing unauthorized operations and data access within Alibaba Cloud.",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"alibaba"}, utils2.AlphaNumeric("30"), true),
		Entropy:     2,
		Keywords:    []string{"alibaba"},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("alibaba", secrets.NewSecret(utils2.AlphaNumeric("30")))
	return utils2.Validate(r, tps, nil)
}
