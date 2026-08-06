package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
)

func TelnyxAPIV2Key() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "telnyx-api-v2-key.1",
		Description: "Telnyx API v2 key.",
		Regex: utils.GenerateSemiGenericRegex(
			[]string{`telnyx(?:[_. -]*(?:api))?[_. -]*(?:secret|key|token)`},
			`KEY[0-9A-Za-z_-]{55}`,
			false,
		),
		Keywords: []string{"telnyx"},
		ValidateExpr: `let r = http.get("https://api.telnyx.com/v2/balance", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 && (r.body contains "\"balance\"") ? {
    "result": "valid"
  } : r.status == 403 ? {
    "result": "valid",
    "reason": "Authenticated but balance access is restricted"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Authentication failed"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.5),
	}

	// validate
	tps := []string{
		`TELNYX_API_KEY=KEY017D98C041711C2B8B6F5A2E50702659_hwntpZaC4XD1OEQEaKWydG`,
	}
	fps := []string{
		`API_KEY=KEY017D98C041711C2B8B6F5A2E50702659_hwntpZaC4XD1OEQEaKWydG`,
		`TELNYX_API_KEY=KEY_short`,
		`TELNYX_API_KEY=KEYxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`,
	}
	return utils.Validate(r, tps, fps)
}
