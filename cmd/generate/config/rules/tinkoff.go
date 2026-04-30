package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func TinkoffAPIToken() *config.Rule {
	r := config.Rule{
		RuleID:      "tinkoff-api-token",
		Description: "Detected a Tinkoff (T-Bank) API token, which may expose access to banking or investment services.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"tinkoff", "tbank"}, `[a-z0-9._-]{50,500}`, true),
		Keywords:    []string{"tinkoff", "tbank"},
		Entropy:     3.5,
	}

	tps := utils.GenerateSampleSecrets("tinkoff", secrets.NewSecretWithEntropy(`[a-z0-9._-]{50,500}`, 3.5))
	fps := []string{
		`tinkoff_merchant_id = "12345"`,
		`tbank_env = "production"`,
	}
	return utils.Validate(r, tps, fps)
}
