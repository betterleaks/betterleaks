package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func GCNotifyAPIKey() *config.Rule {
	uuid := `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`
	r := config.Rule{
		RuleID:      "canadian-digital-service-notify-api-key",
		Description: "Detected a GC Notify API key, which may allow unauthorized notification access.",
		Regex:       regexp.MustCompile(`(?i:\b(ApiKey-v1\s+gcntfy-[a-z0-9_]+-` + uuid + `-` + uuid + `)\b)`),
		Keywords:    []string{"gcntfy-"},
		ValidateExpr: `let r = http.get("https://api.notification.canada.ca/v2/notifications", {
    "Authorization": finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.5),
	}

	return utils.Validate(r,
		[]string{
			`Authorization: "ApiKey-v1 gcntfy-my_test_key-26785a09-ab16-4eb0-8407-a37497a57506-3d844edf-8d35-48ac-975b-e847b4f122b0"`,
			`Authorization: "APIKEY-V1 GCNTFY-MY_TEST_KEY-26785A09-AB16-4EB0-8407-A37497A57506-3D844EDF-8D35-48AC-975B-E847B4F122B0"`,
		},
		[]string{
			`Authorization: "ApiKey-v1 gcntfy-my_test_key-not-a-uuid-3d844edf-8d35-48ac-975b-e847b4f122b0"`,
			`gcntfy-my_test_key-26785a09-ab16-4eb0-8407-a37497a57506-3d844edf-8d35-48ac-975b-e847b4f122b0`,
		},
	)
}
