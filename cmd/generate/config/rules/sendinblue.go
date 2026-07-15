package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
)

func SendInBlueAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "sendinblue-api-token",
		Description: "Identified a Brevo (formerly Sendinblue) API token, which may compromise email marketing services and subscriber data privacy.",
		Regex:       utils.GenerateUniqueTokenRegex(`xkeysib-[A-Za-z0-9_-]{81}`, false),
		Keywords: []string{
			"xkeysib-",
		},
		ValidateExpr: `let r = http.get("https://api.brevo.com/v3/account", {
    "api-key": finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.2),
	}

	return utils.Validate(r,
		[]string{
			`BREVO_API_KEY=xkeysib-abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd-1234567890abcd12`,
			`SENDINBLUE_API_KEY=xkeysib-C6S1LXk_u4mw_uIss4MGmJpH8yrOwFep2aN5YLALYVpAb4buJ7uvxqYfrb3kZL5ao2JvUEFb1vRk79IXj`,
		},
		[]string{
			`BREVO_API_KEY=xkeysib-too-short`,
			`BREVO_API_KEY=xkeysib-C6S1LXk_u4mw_uIss4MGmJpH8yrOwFep2aN5YLALYVpAb4buJ7uvxqYfrb3kZL5ao2JvUEFb1vRk79IXj_extra`,
		},
	)
}
