package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "ibm-cloud-user-api-key",
	Confidence:  "high",
	Description: "Detected an IBM Cloud user API key, which may expose IBM Cloud account resources.",
	Regex:       Assignment([]string{"ibm(?:cloud)?", "bx"}, `(?i)`+AlphaNumericExtendedShort("42,44")),
	Keywords:    []string{"ibm"},
	ValidateExpr: `let r = http.get("https://iam.cloud.ibm.com/v1/apikeys/details?apikey=" + finding["secret"], {
    "Authorization": "Basic Yng6Yng=",
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: MinEntropy(3.5),
	Tests: []config.RuleTest{
		Match("true positive 1", "ibmcloud_apikey = abcdef0123_56789abcdef0123456789abcdef01234", "abcdef0123_56789abcdef0123456789abcdef01234"),
		Match("true positive 2", `ibm_platform_key="f-_RrJDVnuVh07HNTcmnQx_b6CbcQsxmEarVm9P_RWtF"`, "f-_RrJDVnuVh07HNTcmnQx_b6CbcQsxmEarVm9P_RWtF"),
	},
})
