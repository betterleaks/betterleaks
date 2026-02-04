package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func OctopusDeployApiKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "octopus-deploy-api-key",
		Description: "Discovered a potential Octopus Deploy API key, risking application deployments and operational security.",
		Regex:       utils2.GenerateUniqueTokenRegex(`API-[A-Z0-9]{26}`, false),
		Entropy:     3,
		Keywords:    []string{"api-"},
	}

	// validate
	tps := []string{
		utils2.GenerateSampleSecret("octopus", secrets.NewSecret(`API-[A-Z0-9]{26}`)),
		`set apikey="API-ZNRMR7SL6L3ATMOIK7GKJDKLPY"`, // gitleaks:allow
	}
	fps := []string{
		// Invalid start
		`msgstr "GSSAPI-VIRHEKAPSELOINTIMERKKIJONO."`,
		`https://sonarcloud.io/api/project_badges/measure?project=Garden-Coin_API-CalculadoraDeInvestimentos&metric=alert_status`,
		`https://fog-ringer-f42.notion.site/API-BD80F56CDC1441E6BF6011AB6D852875`,    // Invalid end
		`<iframe src="./archive/gifs/api-c99e353f761d318322c853c03e.gif"> </iframe>`, // Wrong case
	}
	return utils2.Validate(r, tps, fps)
}
