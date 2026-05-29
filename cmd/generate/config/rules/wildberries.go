package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func WildberriesAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "wildberries-api-key",
		Description: "Detected a Wildberries API key, which may expose access to seller account and marketplace data.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"wildberries", "wb_api"}, `[a-z0-9._-]{100,300}`, true),
		Keywords:    []string{"wildberries", "wb_api"},
		Entropy:     3.5,
	}

	tps := utils.GenerateSampleSecrets("wildberries", secrets.NewSecretWithEntropy(`[a-z0-9._-]{100,300}`, 3.5))
	fps := []string{
		`wildberries_url = "https://suppliers-api.wildberries.ru"`,
		`wb_api_version = "v3"`,
	}
	return utils.Validate(r, tps, fps)
}
