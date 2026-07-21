package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func PaddleLiveAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "paddle-live-api-key",
		Description: "Paddle live API key.",
		Regex: utils.GenerateUniqueTokenRegex(
			`pdl_live_apikey_[a-z0-9]{26}_[A-Za-z0-9]{22}_[A-Za-z0-9]{3}`,
			false,
		),
		Keywords: []string{"pdl_live_apikey_"},
		ValidateExpr: `let r = http.get("https://api.paddle.com/event-types", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status == 401 || (r.status == 403
    && (r.json?.error?.code ?? "") in ["authentication_malformed", "authentication_invalid"]) ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.5),
	}

	// validate
	tps := []string{
		"PADDLE_API_KEY=pdl_live_apikey_" + secrets.NewSecretWithEntropy(`[a-z0-9]{26}`, 3.5) + "_" + secrets.NewSecretWithEntropy(`[A-Za-z0-9]{22}`, 3.5) + "_" + secrets.NewSecret(`[A-Za-z0-9]{3}`),
	}
	fps := []string{
		`PADDLE_API_KEY=pdl_sdbx_apikey_01kps076233qscw38dxz320d0e_Ab3D5fGb7Jk9LmNpQrStUv_X2z`,
		`PADDLE_API_KEY=pdl_live_apikey_short`,
	}
	return utils.Validate(r, tps, fps)
}
