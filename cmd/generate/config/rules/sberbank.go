package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func SberbankOpenAPIToken() *config.Rule {
	r := config.Rule{
		RuleID:      "sberbank-open-api-token",
		Description: "Detected a Sberbank Open API token, which may expose access to banking services and financial data.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"sberbank"}, `[a-z0-9-]{32,64}`, true),
		Keywords:    []string{"sberbank"},
		Entropy:     3.5,
	}

	tps := utils.GenerateSampleSecrets("sberbank", secrets.NewSecretWithEntropy(`[a-z0-9-]{32,64}`, 3.5))
	fps := []string{
		`sberbank_url = "https://api.sberbank.ru"`,
		`sberbank_env = "sandbox"`,
	}
	return utils.Validate(r, tps, fps)
}
