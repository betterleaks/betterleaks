package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func PrivateAIToken() *config.Rule {
	// https://docs.private-ai.com/reference/latest/operation/metrics_metrics_get/
	r := config.Rule{
		RuleID:      "privateai-api-token",
		Description: "Identified a PrivateAI Token, posing a risk of unauthorized access to AI services and data manipulation.",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"private[_-]?ai"}, `[a-z0-9]{32}`, false),
		Entropy:     3,
		Keywords: []string{
			"privateai",
			"private_ai",
			"private-ai",
		},
	}

	// validate
	tps := []string{
		utils2.GenerateSampleSecret("privateai", secrets.NewSecret(utils2.AlphaNumeric("32"))),
	}
	fps := []string{
		`const privateaiToken = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";`,
	}
	return utils2.Validate(r, tps, fps)
}
