package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func Databricks() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "databricks-api-token",
		Description: "Uncovered a Databricks API token, which may compromise big data analytics platforms and sensitive data processing.",
		Regex:       utils2.GenerateUniqueTokenRegex(`dapi[a-f0-9]{32}(?:-\d)?`, false),
		Entropy:     3,
		Keywords:    []string{"dapi"},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("databricks", "dapi"+secrets.NewSecret(utils2.Hex("32")))
	tps = append(tps, `token = dapif13ac4b49d1cb31f69f678e39602e381-2`) // gitleaks:ignore
	fps := []string{
		`DATABRICKS_TOKEN=dapi123456789012345678a9bc01234defg5`,
	}
	return utils2.Validate(r, tps, fps)
}
