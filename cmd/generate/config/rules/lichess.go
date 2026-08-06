package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func LichessPersonalAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "lichess-personal-access-token",
		Description: "Lichess personal access token.",
		Regex:       utils.GenerateUniqueTokenRegex(`lip_[A-Za-z0-9_]{16,60}`, false),
		Keywords:    []string{"lip_"},
		ValidateExpr: `let r = http.get("https://lichess.org/api/account", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid",
    "username": (r.json?.username ?? "")
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.5),
	}

	// validate
	tps := []string{
		"LICHESS_TOKEN=lip_" + secrets.NewSecretWithEntropy(`[A-Za-z0-9_]{32}`, 3.5),
	}
	fps := []string{
		`LICHESS_TOKEN=lip_short`,
	}
	return utils.Validate(r, tps, fps)
}
