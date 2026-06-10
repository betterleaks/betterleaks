package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
)

func KlaviyoAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "klaviyo-api-key",
		Description: "Detected a Klaviyo API key, which may expose Klaviyo account and marketing data.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"klaviyo"}, `pk_`+utils.AlphaNumeric("34"), true),
		Keywords:    []string{"klaviyo"},
		ValidateCEL: `cel.bind(r,
  http.get("https://a.klaviyo.com/api/accounts", {
    "Revision": "2023-02-22",
    "Authorization": "Klaviyo-API-Key " + finding["secret"],
    "Accept": "application/json"
  }),
  r.status == 200 && r.body.contains("\"data\"") ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)
)`,
		Filter: utils.MinEntropy(3.5),
	}

	tps := []string{
		`klaviyo_key = pk_abcd1234fghij5678klmn9012opqr3456s`,
		`KLAVIYO_API_KEY=pk_ABCd1234fghij5678klmn9012opqr3456s`,
	}
	return utils.Validate(r, tps, nil)
}
