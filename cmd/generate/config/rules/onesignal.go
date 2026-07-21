package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func OneSignalRichAuthenticationToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "onesignal-rich-authentication-token",
		Description: "OneSignal rich authentication token.",
		Regex:       utils.GenerateUniqueTokenRegex(`os_v2_(?:app|org)_[a-z2-7]{103}`, false),
		Keywords:    []string{"os_v2_app_", "os_v2_org_"},
		ValidateExpr: `let r = http.get("https://api.onesignal.com/apps", {
    "Authorization": "Key " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 || (r.status == 403 && size(r.json?.errors ?? []) > 0) ? {
    "result": "valid"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.5),
	}

	// validate
	tps := []string{
		"ONESIGNAL_API_KEY=os_v2_app_" + secrets.NewSecretWithEntropy(`[a-z2-7]{103}`, 3.5),
		"ONESIGNAL_ORG_API_KEY=os_v2_org_" + secrets.NewSecretWithEntropy(`[a-z2-7]{103}`, 3.5),
	}
	fps := []string{
		`ONESIGNAL_APP_ID=202d4f61-1ca9-42df-9d36-bb17d8123abc`,
		`ONESIGNAL_API_KEY=os_v2_app_short`,
	}
	return utils.Validate(r, tps, fps)
}
