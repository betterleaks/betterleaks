package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "resend-api-key.1",
	Confidence:  "high",
	Description: "Resend API key, which may allow sending email or managing account resources.",
	Regex:       rulebuilder.Token(`re_[1-9A-HJ-NP-Za-km-z]{8}_[1-9A-HJ-NP-Za-km-z]{24}`),
	Keywords:    []string{"resend"},
	ValidateExpr: `let r = http.get("https://api.resend.com/domains", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json",
    "User-Agent": "betterleaks-secret-validation/1"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status == 401 && (r.body contains "restricted_api_key") ? {
    "result": "valid",
    "reason": "Authenticated sending-only API key"
  } : r.status == 403 && (r.body contains "invalid_api_key") ? {
    "result": "invalid",
    "reason": "Invalid API key"
  } : validate.unknown(r)`,
	FilterExpr: rulebuilder.MinEntropy(3.5),
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "RESEND_API_KEY=re_hDTaBGRX_xcWigjiDhDTaBGRXeJ6ZzZ7q", "re_hDTaBGRX_xcWigjiDhDTaBGRXeJ6ZzZ7q"),
		rulebuilder.Match("true positive 2", "RESEND_AUTHORIZATION=Bearer re_hDTaBGRX_xcWigjiDhDTaBGRXeJ6ZzZ7q", "re_hDTaBGRX_xcWigjiDhDTaBGRXeJ6ZzZ7q"),
		rulebuilder.NoMatch("false positive 1", "RESEND_API_KEY=re_short"),
		rulebuilder.NoMatch("false positive 2", "RESEND_API_KEY=re_0OtIl123_0OtIl1234567890123456789"),
		rulebuilder.NoMatch("false positive 3", "RESEND_API_KEY=re_AAAAAAAA_AAAAAAAAAAAAAAAAAAAAAAAA"),
	},
})
