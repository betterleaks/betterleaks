package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func AsaasAPIToken() *config.Rule {
	r := config.Rule{
		RuleID:      "asaas-api-token",
		Description: "Detected an Asaas API token, which may expose payment and customer data.",
		Regex:       regexp.MustCompile(`(?:^|[^A-Za-z0-9_-])(\$aact_(?:prod|hmlg)_[A-Za-z0-9_-]{20,100})(?:[^A-Za-z0-9_-]|$)`),
		Keywords:    []string{"$aact_"},
		ValidateExpr: `let url = finding["secret"].contains("$aact_hmlg_") ? "https://api-sandbox.asaas.com/v3/myAccount/commercialInfo/" : "https://api.asaas.com/v3/myAccount/commercialInfo/";
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
		Filter: utils.MinEntropy(3.5),
	}

	return utils.Validate(r,
		[]string{
			`ASAAS_API_KEY=$aact_prod_abcdefghijklmnop1234567890ABCDEF`,
			`api_token: "$aact_hmlg_1234567890abcdefghijklmnopQRSTUV"`,
		},
		[]string{
			`ASAAS_API_KEY=$aact_dev_abcdefghijklmnop1234567890ABCDEF`,
			`ASAAS_API_KEY=$aact_prod_too_short`,
		},
	)
}
