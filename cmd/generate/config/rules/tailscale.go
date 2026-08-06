package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func TailscaleAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "tailscale-api-key.1",
		Description: "Tailscale API access token.",
		Regex:       utils.GenerateUniqueTokenRegex(`tskey-api-[A-Za-z0-9_-]{20,36}`, false),
		Keywords:    []string{"tskey-api-"},
		ValidateExpr: `let r = http.post("https://api.tailscale.com/api/v2/secret-scanning/verify", {
    "Content-Type": "application/x-www-form-urlencoded",
    "Accept": "application/json"
  }, "key=" + finding["secret"]); r.status == 204 ? {
    "result": "valid"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Invalid API token"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.0),
	}

	// validate
	tps := []string{
		"TAILSCALE_API_KEY=tskey-api-" + secrets.NewSecretWithEntropy(`[A-Za-z0-9]{12}`, 3.0) + "-" + secrets.NewSecret(`[A-Za-z0-9]{18}`),
	}
	fps := []string{
		`TAILSCALE_API_KEY=tskey-api-short`,
		`TAILSCALE_AUTH_KEY=tskey-auth-abcDEF1CNTRL-091234567890ABCDEF`,
	}
	return utils.Validate(r, tps, fps)
}
