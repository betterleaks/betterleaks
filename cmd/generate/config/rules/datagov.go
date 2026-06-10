package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
)

func DataGovAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "datagov-api-key",
		Description: "Detected a Data.gov API key, which may expose usage of Data.gov-backed APIs.",
		Regex:       utils.GenerateSemiGenericRegex([]string{`data\.gov`}, utils.AlphaNumeric("40"), true),
		Keywords:    []string{"data.gov"},
		ValidateCEL: `cel.bind(r,
  http.get("https://developer.nrel.gov/api/alt-fuel-stations/v1.json?limit=1&api_key=" + finding["secret"], {
    "Accept": "application/json"
  }),
  r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)
)`,
		Filter: utils.MinEntropy(3.5),
	}

	tps := []string{
		`data.gov_api_key=pBZm2kXbuPdRfzYyarRT0bvcWAisnJg98YJzBJyJ`,
		`data.gov_token=plZJDnKs4OrPeV8wgBr2fYO6VnXb1YPEcVaZbnYI`,
	}
	return utils.Validate(r, tps, nil)
}
