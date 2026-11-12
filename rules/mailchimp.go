package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

// https://mailchimp.com/developer/marketing/api/root/
const mailchimpValidateExpr = `let dc = finding["secret"][lastIndexOf(finding["secret"], "-") + 1:];
let r = http.get("https://" + dc + ".api.mailchimp.com/3.0/", {"Authorization": "Basic " + base64.encode(bytes("x:" + finding["secret"])), "Accept": "application/json"});
r.status == 200 && type(r.json) == "map" && (r.json?.account_id ?? "") != "" ? {
  "result": "valid",
  "analysis": {
    "identity": {
      "username": string(r.json?.username ?? ""),
      "email": string(r.json?.email ?? ""),
      "account": {
        "id": string(r.json?.account_id ?? ""),
        "name": string(r.json?.account_name ?? "")
      }
    },
    "metadata": {
      "datacenter": dc,
      "role": string(r.json?.role ?? "")
    }
  }
} : r.status == 401 ? {
  "result": "invalid", "reason": "Unauthorized"
} : validate.unknown(r)`

const mailchimpAnalyzeExpr = rulebuilder.IdentityOnlyAnalyzeExpr

var _ = rulebuilder.Add(config.Rule{
	ID:          "mailchimp-api-key",
	Confidence:  "high",
	Description: "Identified a Mailchimp API key, potentially compromising email marketing campaigns and subscriber data.",
	Regex:       rulebuilder.Assignment([]string{"MailchimpSDK.initialize", "mailchimp"}, `(?i)[a-f0-9]{32}-us\d\d`),
	Keywords: []string{
		"mailchimp",
	},
	ValidateExpr: mailchimpValidateExpr,
	AnalyzeExpr:  mailchimpAnalyzeExpr,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `mailchimpToken = "1f7b169c846f218ab552fa82fbf86758-us20"`, "1f7b169c846f218ab552fa82fbf86758-us20"),
		rulebuilder.Match("true positive 1", "mailchimp_api_key: cefa780880ba5f5696192a34f6292c35-us18", "cefa780880ba5f5696192a34f6292c35-us18"),
		rulebuilder.Match("true positive 2", `MAILCHIMPE_KEY = "b5b9f8e50c640da28993e8b6a48e3e53-us18"`, "b5b9f8e50c640da28993e8b6a48e3e53-us18"),
		rulebuilder.NoMatch("false positive 1", "MailchimpSDK.initialize(token: 3012a5754bbd716926f99c028f7ea428-us18)"),
	},
})
