package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
	"github.com/betterleaks/betterleaks/regexp"
)

func LinearAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "linear-api-key",
		Description: "Detected a Linear API Token, posing a risk to project management tools and sensitive task data.",
		Regex:       regexp.MustCompile(`lin_api_(?i)[a-z0-9]{40}`),
		Entropy:     2,
		Keywords:    []string{"lin_api_"},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("linear", "lin_api_"+secrets.NewSecret(utils2.AlphaNumeric("40")))
	return utils2.Validate(r, tps, nil)
}

func LinearClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "linear-client-secret",
		Description: "Identified a Linear Client Secret, which may compromise secure integrations and sensitive project management data.",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"linear"}, utils2.Hex("32"), true),
		Entropy:     2,
		Keywords:    []string{"linear"},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("linear", secrets.NewSecret(utils2.Hex("32")))
	return utils2.Validate(r, tps, nil)
}
