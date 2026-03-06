package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func PrivateAIToken() *config.Rule {
	// https://docs.private-ai.com/reference/latest/operation/metrics_metrics_get/
	r := config.Rule{
		RuleID:      "privateai-api-token",
		Description: "Identified a PrivateAI Token, posing a risk of unauthorized access to AI services and data manipulation.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"private[_-]?ai"}, `[a-z0-9]{32}`, false),
		Entropy:     3,
		Keywords: []string{
			"privateai",
			"private_ai",
			"private-ai",
		},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("privateai", secrets.NewSecretWithEntropy(utils.AlphaNumeric("32"), 3)),
	}
	fps := []string{
		`const privateaiToken = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";`,
	}
	return utils.Validate(r, tps, fps)
}
