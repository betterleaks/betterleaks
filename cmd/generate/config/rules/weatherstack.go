package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func WeatherstackAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "weatherstack-api-key.1",
		Description: "Weatherstack API key.",
		Regex: utils.GenerateSemiGenericRegex(
			[]string{`weatherstack(?:[_. -]*(?:api))?[_. -]*(?:secret|key|token)`},
			`[0-9a-z]{32}`,
			false,
		),
		Keywords: []string{"weatherstack"},
		ValidateExpr: `let r = http.get("https://api.weatherstack.com/current?access_key=" + finding["secret"] + "&query=Los%20Angeles", {
    "Accept": "application/json"
  }); r.status == 200 && ((r.body contains "\"location\"") || (r.body contains "Access Restricted - Your current Subscription Plan does not support HTTPS Encryption")) ? {
    "result": "valid"
  } : r.status == 401 && (r.body contains "\"invalid_access_key\"") ? {
    "result": "invalid",
    "reason": "Invalid access key"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.0),
	}

	// validate
	tps := []string{
		"WEATHERSTACK_API_KEY=" + secrets.NewSecretWithEntropy(`[0-9a-z]{32}`, 3.0),
	}
	fps := []string{
		`API_KEY=abcdef0123456789abcdef0123456789`,
		`WEATHERSTACK_API_KEY=short`,
		`WEATHERSTACK_API_KEY=00000000000000000000000000000000`,
	}
	return utils.Validate(r, tps, fps)
}
