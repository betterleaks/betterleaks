package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

const highnoteLiveValidationExpr = `let r = http.post("https://api.us.highnote.com/graphql", {
    "Authorization": "Basic " + base64.encode(bytes(finding["secret"])),
    "Content-Type": "application/json",
    "Accept": "application/json"
  }, "{\"query\":\"query { ping }\"}"); r.status == 200 && (r.json?.data?.ping ?? "") == "pong" ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`

func HighnoteSecretLiveKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:       "highnote-secret-live-key",
		Description:  "Highnote secret API key for the live environment.",
		Regex:        regexp.MustCompile(`\b(sk_live_a2V5Xz[A-Za-z0-9+/]{69}={0,2})`),
		Keywords:     []string{"sk_live_a2V5Xz"},
		ValidateExpr: highnoteLiveValidationExpr,
		Filter:       utils.MinEntropy(3.5),
	}

	// validate
	tps := []string{
		"HIGHNOTE_SK_LIVE=\"sk_live_a2V5Xz" + secrets.NewSecretWithEntropy(`[A-Za-z0-9+/]{69}`, 3.5) + "\"",
	}
	fps := []string{
		`HIGHNOTE_SK_LIVE="sk_live_short"`,
	}
	return utils.Validate(r, tps, fps)
}
