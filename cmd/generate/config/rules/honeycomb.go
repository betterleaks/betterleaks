package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
)

func HoneycombAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "honeycomb-api-key",
		Description: "Detected a Honeycomb API key, which may expose Honeycomb telemetry and environment data.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"honeycomb"}, `(?:`+utils.Hex("32")+`|`+utils.AlphaNumeric("22")+`)`, true),
		Keywords:    []string{"honeycomb"},
		ValidateCEL: `cel.bind(r,
  http.get("https://api.honeycomb.io/1/auth", {
    "X-Honeycomb-Team": finding["secret"],
    "Accept": "application/json"
  }),
  r.status == 200 && r.body.contains("\"team\"") ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)
)`,
		Filter: utils.MinEntropy(3.5),
	}

	tps := []string{
		`honeycomb_secret_key=8f14e45fceea167a5a36dedd4bea2543`,
		`honeycomb_token=z0d1f2bcaloumn3456789P`,
	}
	return utils.Validate(r, tps, nil)
}
