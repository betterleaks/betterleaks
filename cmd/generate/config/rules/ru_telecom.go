package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func MTSAPIToken() *config.Rule {
	r := config.Rule{
		RuleID:      "mts-api-token",
		Description: "Detected an MTS API token, which may expose access to MTS telecom services.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"mts"}, `[a-z0-9]{32,64}`, true),
		Keywords:    []string{"mts"},
		Entropy:     3.5,
	}

	tps := utils.GenerateSampleSecrets("mts", secrets.NewSecretWithEntropy(`[a-z0-9]{32,64}`, 3.5))
	fps := []string{
		`mts_operator = "mts"`,
		`mts_region = "moscow"`,
	}
	return utils.Validate(r, tps, fps)
}

func BeelineAPIToken() *config.Rule {
	r := config.Rule{
		RuleID:      "beeline-api-token",
		Description: "Detected a Beeline API token, which may expose access to Beeline telecom services.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"beeline"}, `[a-z0-9]{32,64}`, true),
		Keywords:    []string{"beeline"},
		Entropy:     3.5,
	}

	tps := utils.GenerateSampleSecrets("beeline", secrets.NewSecretWithEntropy(`[a-z0-9]{32,64}`, 3.5))
	fps := []string{
		`beeline_url = "https://apiv2.beeline.ru"`,
		`beeline_env = "test"`,
	}
	return utils.Validate(r, tps, fps)
}

func MegafonAPIToken() *config.Rule {
	r := config.Rule{
		RuleID:      "megafon-api-token",
		Description: "Detected a MegaFon API token, which may expose access to MegaFon telecom services.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"megafon"}, `[a-z0-9]{32,64}`, true),
		Keywords:    []string{"megafon"},
		Entropy:     3.5,
	}

	tps := utils.GenerateSampleSecrets("megafon", secrets.NewSecretWithEntropy(`[a-z0-9]{32,64}`, 3.5))
	fps := []string{
		`megafon_url = "https://api.megafon.ru"`,
		`megafon_env = "production"`,
	}
	return utils.Validate(r, tps, fps)
}

func Tele2APIToken() *config.Rule {
	r := config.Rule{
		RuleID:      "tele2-api-token",
		Description: "Detected a Tele2 API token, which may expose access to Tele2 telecom services.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"tele2"}, `[a-z0-9]{32,64}`, true),
		Keywords:    []string{"tele2"},
		Entropy:     3.5,
	}

	tps := utils.GenerateSampleSecrets("tele2", secrets.NewSecretWithEntropy(`[a-z0-9]{32,64}`, 3.5))
	fps := []string{
		`tele2_url = "https://api.tele2.ru"`,
		`tele2_env = "staging"`,
	}
	return utils.Validate(r, tps, fps)
}
