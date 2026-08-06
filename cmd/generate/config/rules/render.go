package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func RenderAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:       "render-api-key",
		Description:  "Detected a Render API key, which may expose hosted services and account resources to unauthorized access.",
		Regex:        utils.GenerateUniqueTokenRegex(`rnd_[A-Za-z0-9]{28}`, false),
		Keywords:     []string{"rnd_"},
		ValidateExpr: utils.BearerGetValidationExpr("https://api.render.com/v1/services?limit=1", "true"),
		Filter:       utils.MinEntropy(3.5),
	}

	tps := utils.GenerateSampleSecrets("render", "rnd_"+secrets.NewSecretWithEntropy(`[A-Za-z0-9]{28}`, 3.5))
	fps := []string{
		`rnd_jYBekhjOgICntzWUNO2ye4yCNKb`,
		`rnd_jYBekhjOgICntzWUNO2ye4y_NKbk`,
	}
	return utils.Validate(r, tps, fps)
}
