package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func OzonAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "ozon-api-key",
		Description: "Detected an OZON Seller API key, which may expose access to seller account data and marketplace operations.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"ozon"}, `[a-z0-9-]{36,64}`, true),
		Keywords:    []string{"ozon"},
		Entropy:     3.0,
	}

	tps := utils.GenerateSampleSecrets("ozon", secrets.NewSecretWithEntropy(`[a-z0-9-]{36,64}`, 3.0))
	fps := []string{
		`ozon_url = "https://api-seller.ozon.ru"`,
		`ozon_client_id = "12345"`,
	}
	return utils.Validate(r, tps, fps)
}
