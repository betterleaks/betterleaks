package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func DatadogAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "datadog-api-key",
		Description: "Detected a Datadog API key, potentially risking monitoring and analytics data exposure and manipulation.",
		Regex: utils.GenerateSemiGenericRegex([]string{"datadog"},
			utils.AlphaNumeric("32"), true),
		Keywords: []string{
			"datadog",
		},
		ValidateCEL: `cel.bind(r,
  http.get("https://api.datadoghq.com/api/v1/validate", {
    "Accept": "application/json",
    "DD-API-KEY": finding["secret"]
  }),
  r.status == 200 && !r.body.contains("\"Forbidden\"") ? {
    "result": "valid"
  } : r.status in [401, 403] || r.body.contains("\"Forbidden\"") ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)
)`,
		Filter: utils.MinEntropy(3.5),
	}

	tps := utils.GenerateSampleSecrets("datadog", secrets.NewSecret(utils.AlphaNumeric("32")))
	tps = append(tps, `DATADOG_API_KEY=0024a29224affe29d173c0bf99e5a89d`)
	return utils.Validate(r, tps, nil)
}

func DatadogApplicationKey() *config.Rule {
	r := config.Rule{
		RuleID:      "datadog-application-key",
		Description: "Detected a Datadog application key, which may expose Datadog account and monitoring data when paired with an API key.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"datadog"}, `[A-Za-z0-9-]{40}`, true),
		Keywords: []string{
			"datadog",
		},
		Filter: utils.MinEntropy(3.5),
	}

	tps := []string{
		`DATADOG_APPLICATION_KEY=abcDEF0123456789abcDEF0123456789abcDEF01`,
	}
	return utils.Validate(r, tps, nil)
}
