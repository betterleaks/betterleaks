package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
)

func EtsyAccessToken() *config.Rule {
	r := config.Rule{
		RuleID:      "etsy-open-api-key",
		Description: "Found an Etsy Open API key, potentially compromising Etsy app access and shop integrations.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"etsy", "x-api-key"}, utils.AlphaNumeric("24")+`:`+utils.AlphaNumeric("10,64"), true),
		Keywords: []string{
			"etsy",
			"x-api-key",
		},
		ValidateCEL: `cel.bind(k,
  finding["secret"].split(":")[0],
  cel.bind(r,
    http.get("https://api.etsy.com/v3/application/openapi-ping", {
      "x-api-key": k,
      "Accept": "application/json"
    }),
    r.status == 200 ? {
      "result": "valid"
    } : r.status in [401, 403] ? {
      "result": "invalid",
      "reason": "Unauthorized"
    } : validate.unknown(r)
  )
)`,
		Filter: utils.MinEntropy(3.0),
	}

	tps := []string{
		`x-api-key: 1aa2bb33c44d55eeeeee6fff:a1b2c3d4e5`,
		`ETSY_API_KEY=1aa2bb33c44d55eeeeee6fff:a1b2c3d4e5`,
	}
	fps := []string{
		`ETSY_API_KEY=your_api_key:your_key_here`,
	}
	return utils.Validate(r, tps, fps)
}
