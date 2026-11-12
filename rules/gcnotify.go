package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "canadian-digital-service-notify-api-key",
	Confidence:  "high",
	Description: "Detected a GC Notify API key, which may allow unauthorized notification access.",
	Regex:       `(?i:\b(ApiKey-v1\s+gcntfy-[a-z0-9_]+-` + rulebuilder.Hex8_4_4_4_12() + `-` + rulebuilder.Hex8_4_4_4_12() + `)\b)`,
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
	FilterExpr: rulebuilder.MinEntropy(3.5),
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", `Authorization: "ApiKey-v1 gcntfy-my_test_key-26785a09-ab16-4eb0-8407-a37497a57506-3d844edf-8d35-48ac-975b-e847b4f122b0"`, "ApiKey-v1 gcntfy-my_test_key-26785a09-ab16-4eb0-8407-a37497a57506-3d844edf-8d35-48ac-975b-e847b4f122b0"),
		rulebuilder.Match("true positive 2", `Authorization: "APIKEY-V1 GCNTFY-MY_TEST_KEY-26785A09-AB16-4EB0-8407-A37497A57506-3D844EDF-8D35-48AC-975B-E847B4F122B0"`, "APIKEY-V1 GCNTFY-MY_TEST_KEY-26785A09-AB16-4EB0-8407-A37497A57506-3D844EDF-8D35-48AC-975B-E847B4F122B0"),
		rulebuilder.NoMatch("false positive 1", `Authorization: "ApiKey-v1 gcntfy-my_test_key-not-a-uuid-3d844edf-8d35-48ac-975b-e847b4f122b0"`),
		rulebuilder.NoMatch("false positive 2", "gcntfy-my_test_key-26785a09-ab16-4eb0-8407-a37497a57506-3d844edf-8d35-48ac-975b-e847b4f122b0"),
	},
})
