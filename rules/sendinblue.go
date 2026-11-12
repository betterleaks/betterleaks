package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

// https://developers.brevo.com/reference/get-account
const brevoValidateExpr = `let r = http.get("https://api.brevo.com/v3/account", {
  "api-key": finding["secret"],
  "Accept": "application/json"
});
r.status == 200 && type(r.json) == "map" && (r.json?.email ?? "") != "" ? {
  "result": "valid",
  "analysis": {
    "identity": {
      "id": string(r.json?.user_id ?? ""),
      "email": string(r.json?.email ?? ""),
      "name": trim((r.json?.firstName ?? "") + " " + (r.json?.lastName ?? "")),
      "account": {
        "id": string(r.json?.organization_id ?? ""),
        "name": string(r.json?.companyName ?? "")
      }
    },
    "metadata": {}
  }
} : r.status == 401 ? {
  "result": "invalid", "reason": "Unauthorized"
} : validate.unknown(r)`

const brevoAnalyzeExpr = rulebuilder.IdentityOnlyAnalyzeExpr

var _ = rulebuilder.Add(config.Rule{
	ID:          "sendinblue-api-token",
	Confidence:  "high",
	Description: "Identified a Brevo (formerly Sendinblue) API token, which may compromise email marketing services and subscriber data privacy.",
	Regex:       `\b(xkeysib-[a-fA-F0-9]{64}-[a-zA-Z0-9]{16})\b`,
	Keywords: []string{
		"xkeysib-",
	},
	ValidateExpr: brevoValidateExpr,
	AnalyzeExpr:  brevoAnalyzeExpr,
	FilterExpr:   rulebuilder.MinEntropy(3.2),
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "BREVO_API_KEY=xkeysib-abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd-1234567890abcd12", "xkeysib-abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd-1234567890abcd12"),
		rulebuilder.Match("true positive 2", "SENDINBLUE_API_KEY=xkeysib-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef-ab12cd34ef56gh78", "xkeysib-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef-ab12cd34ef56gh78"),
		rulebuilder.Match("true positive 3", "BREVO_KEYS=[xkeysib-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef-ab12cd34ef56gh78]", "xkeysib-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef-ab12cd34ef56gh78"),
		rulebuilder.NoMatch("false positive 1", "BREVO_API_KEY=xkeysib-too-short"),
		rulebuilder.NoMatch("false positive 2", "BREVO_API_KEY=xkeysib-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef-ab12cd34ef56gh78_extra"),
	},
})
