package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "ibm-cloud-user-api-key",
	Confidence:  "high",
	Description: "Detected an IBM Cloud user API key, which may expose IBM Cloud account resources.",
	Regex:       rulebuilder.Assignment([]string{"ibm(?:cloud)?", "bx"}, `(?i)[a-z0-9_-]{42,44}`),
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
	// Word-built names, such as a C macro in a USB_VENDOR_ID_IBM device
	// table, tokenize efficiently; generated keys do not.
	FilterExpr: rulebuilder.MinEntropyAndTokenEfficiency,
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "ibmcloud_apikey = q7xv0dk2m9rj5t_nb3fw8hz1ycp46sg0aue7ridk29j", "q7xv0dk2m9rj5t_nb3fw8hz1ycp46sg0aue7ridk29j"),
		rulebuilder.Match("true positive 2", `ibm_platform_key="f-_RrJDVnuVh07HNTcmnQx_b6CbcQsxmEarVm9P_RWtF"`, "f-_RrJDVnuVh07HNTcmnQx_b6CbcQsxmEarVm9P_RWtF"),
		rulebuilder.NoMatch("macro argument", `{ HID_USB_DEVICE(USB_VENDOR_ID_IBM, USB_DEVICE_ID_IBM_SCROLLPOINT_800DPI_OPTICAL) },`),
	},
})
