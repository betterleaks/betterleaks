package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func ResendAPIKey() *config.Rule {
	const base58 = `[1-9A-HJ-NP-Za-km-z]`
	r := config.Rule{
		RuleID:      "resend-api-key.1",
		Confidence:  "high",
		Description: "Resend API key, which may allow sending email or managing account resources.",
		Regex:       utils.GenerateUniqueTokenRegex(`re_`+base58+`{8}_`+base58+`{24}`, false),
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
		Filter: utils.MinEntropy(3.5),
	}

	key := "re_" +
		secrets.NewSecretWithEntropy(base58+`{8}`, 3.0) + "_" +
		secrets.NewSecretWithEntropy(base58+`{24}`, 3.5)
	tps := []string{
		`RESEND_API_KEY=` + key,
		`RESEND_AUTHORIZATION=Bearer ` + key,
	}
	fps := []string{
		`RESEND_API_KEY=re_short`,
		`RESEND_API_KEY=re_0OtIl123_0OtIl1234567890123456789`,
		`RESEND_API_KEY=re_AAAAAAAA_AAAAAAAAAAAAAAAAAAAAAAAA`,
	}
	return utils.Validate(r, tps, fps)
}
