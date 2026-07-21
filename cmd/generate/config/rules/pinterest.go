package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func PinterestAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "pinterest-access-token",
		Description: "Pinterest access token.",
		Regex:       utils.GenerateUniqueTokenRegex(`pina_[A-Za-z0-9_-]{20,200}`, false),
		Keywords:    []string{"pina_"},
		ValidateExpr: `let r = http.get("https://api.pinterest.com/v5/user_account", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 && r.json?.username != null ? {
    "result": "valid"
  } : r.status == 403 ? {
    "result": "valid",
    "reason": "Authenticated but user-account access is restricted"
  } : r.status == 401 && (r.json?.code ?? 0) == 2 ? {
    "result": "invalid",
    "reason": "Authentication failed"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.5),
	}

	// validate
	tps := []string{
		"PINTEREST_ACCESS_TOKEN=pina_" + secrets.NewSecretWithEntropy(`[A-Za-z0-9_-]{40}`, 3.5),
	}
	fps := []string{
		`PINTEREST_ACCESS_TOKEN=pina_short`,
		`PINTEREST_ACCESS_TOKEN=pina_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`,
	}
	return utils.Validate(r, tps, fps)
}
