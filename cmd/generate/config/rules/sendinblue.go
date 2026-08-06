package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func SendInBlueAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "sendinblue-api-token",
		Description: "Identified a Brevo (formerly Sendinblue) API token, which may compromise email marketing services and subscriber data privacy.",
		Regex:       regexp.MustCompile(`\b(xkeysib-[a-fA-F0-9]{64}-[a-zA-Z0-9]{16})\b`),
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
			`SENDINBLUE_API_KEY=xkeysib-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef-ab12cd34ef56gh78`,
			`BREVO_KEYS=[xkeysib-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef-ab12cd34ef56gh78]`,
		},
		[]string{
			`BREVO_API_KEY=xkeysib-too-short`,
			`BREVO_API_KEY=xkeysib-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef-ab12cd34ef56gh78_extra`,
		},
	)
}
