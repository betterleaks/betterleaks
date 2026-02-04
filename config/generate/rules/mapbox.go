package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func MapBox() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Detected a MapBox API token, posing a risk to geospatial services and sensitive location data exposure.",
		RuleID:      "mapbox-api-token",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"mapbox"}, `pk\.[a-z0-9]{60}\.[a-z0-9]{22}`, true),

		Keywords: []string{"mapbox"},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("mapbox", "pk."+secrets.NewSecret(utils2.AlphaNumeric("60"))+"."+secrets.NewSecret(utils2.AlphaNumeric("22")))
	return utils2.Validate(r, tps, nil)
}
