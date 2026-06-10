package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
)

func IBMCloudUserAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "ibm-cloud-user-api-key",
		Description: "Detected an IBM Cloud user API key, which may expose IBM Cloud account resources.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"ibm(?:cloud)?", "bx"}, utils.AlphaNumericExtendedShort("42,44"), true),
		Keywords:    []string{"ibm"},
		ValidateCEL: `cel.bind(r,
  http.get("https://iam.cloud.ibm.com/v1/apikeys/details?apikey=" + finding["secret"], {
    "Authorization": "Basic Yng6Yng=",
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
		`ibmcloud_apikey = abcdef0123_56789abcdef0123456789abcdef01234`,
		`ibm_platform_key="f-_RrJDVnuVh07HNTcmnQx_b6CbcQsxmEarVm9P_RWtF"`,
	}
	return utils.Validate(r, tps, nil)
}
