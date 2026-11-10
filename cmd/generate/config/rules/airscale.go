package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

func AirscaleAPIKey() *config.Rule {
	r := config.Rule{
		Description: "Detected an Airscale API key, which may allow unauthorized access to Airscale enrichment and lead data.",
		ID:          "airscale-api-key",
		Confidence:  "high",
		Regex:       utils.GenerateSemiGenericRegex([]string{"airscale"}, utils.AlphaNumeric("30"), true),
		Keywords:    []string{"airscale"},
		FilterExpr:  `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	}

	tps := utils.GenerateSampleSecrets("airscale", secrets.NewSecretWithEntropy(utils.AlphaNumeric("30"), 3.5))
	fps := []string{
		`AIRSCALE_API_KEY=YOUR_API_KEY`,
		`Authorization: Bearer $AIRSCALE_API_KEY`,
	}
	return utils.Validate(r, tps, fps)
}
