package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "asaas-api-token",
	Confidence:  "high",
	Description: "Detected an Asaas API token, which may expose payment and customer data.",
	Regex:       `(?:^|[^A-Za-z0-9_-])(\$aact_(?:prod|hmlg)_[A-Za-z0-9_-]{20,100})(?:[^A-Za-z0-9_-]|$)`,
	Keywords:    []string{"$aact_"},
	ValidateExpr: `let url = (finding["secret"] contains "$aact_hmlg_") ? "https://api-sandbox.asaas.com/v3/myAccount/commercialInfo/" : "https://api.asaas.com/v3/myAccount/commercialInfo/";
let r = http.get(url, {
    "access_token": finding["secret"],
    "Accept": "application/json",
    "User-Agent": "betterleaks"
  }); r.status == 200 && (r.body contains "\"commercialInfo\"") ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: MinEntropy(3.5),
	Tests: []config.RuleTest{
		Match("true positive 1", "ASAAS_API_KEY=$aact_prod_abcdefghijklmnop1234567890ABCDEF", "$aact_prod_abcdefghijklmnop1234567890ABCDEF"),
		Match("true positive 2", `api_token: "$aact_hmlg_1234567890abcdefghijklmnopQRSTUV"`, "$aact_hmlg_1234567890abcdefghijklmnopQRSTUV"),
		NoMatch("false positive 1", "ASAAS_API_KEY=$aact_dev_abcdefghijklmnop1234567890ABCDEF"),
		NoMatch("false positive 2", "ASAAS_API_KEY=$aact_prod_too_short"),
	},
})
