package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func OpenWeatherAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "openweather-api-key",
		Description: "OpenWeather API key.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"openweather", "pyowm"}, `[a-z0-9]{32}`, false),
		Keywords:    []string{"openweather", "pyowm"},
		ValidateExpr: `let r = http.get("https://api.openweathermap.org/data/2.5/forecast?q=London&appid=" + finding["secret"], {
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.5),
	}

	// validate
	tps := []string{
		"OPENWEATHER_API_KEY=" + secrets.NewSecretWithEntropy(`[a-z0-9]{32}`, 3.5),
		"pyowm='" + secrets.NewSecretWithEntropy(`[a-z0-9]{32}`, 3.5) + "'",
	}
	fps := []string{
		`OPENWEATHER_API_KEY=abcdef1234567890`,
		`OPENWEATHER_API_KEY=00000000000000000000000000000000`,
	}
	return utils.Validate(r, tps, fps)
}
