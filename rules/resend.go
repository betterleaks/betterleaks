package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(ResendAPIKey())

func ResendAPIKey() config.Rule {
	const base58 = `[1-9A-HJ-NP-Za-km-z]`
	r := config.Rule{
		ID:          "resend-api-key.1",
		Confidence:  "high",
		Description: "Resend API key, which may allow sending email or managing account resources.",
		Regex:       Token(`re_` + base58 + `{8}_` + base58 + `{24}`),
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
		FilterExpr: MinEntropy(3.5),
	}
	r.Tests = []config.RuleTest{
		Match("true positive 1", "RESEND_API_KEY=re_hDTaBGRX_xcWigjiDhDTaBGRXeJ6ZzZ7q", "re_hDTaBGRX_xcWigjiDhDTaBGRXeJ6ZzZ7q"),
		Match("true positive 2", "RESEND_AUTHORIZATION=Bearer re_hDTaBGRX_xcWigjiDhDTaBGRXeJ6ZzZ7q", "re_hDTaBGRX_xcWigjiDhDTaBGRXeJ6ZzZ7q"),
		NoMatch("false positive 1", "RESEND_API_KEY=re_short"),
		NoMatch("false positive 2", "RESEND_API_KEY=re_0OtIl123_0OtIl1234567890123456789"),
		NoMatch("false positive 3", "RESEND_API_KEY=re_AAAAAAAA_AAAAAAAAAAAAAAAAAAAAAAAA"),
	}
	return r
}
