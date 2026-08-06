package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

const wakaTimeAPIKeyValidateExpr = `let r = http.get("https://api.wakatime.com/api/v1/users/current?api_key=" + finding["secret"], {
    "Accept": "application/json"
  }); r.status == 200 && (r.body contains "\"data\"") ? {
    "result": "valid"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`

func WakaTimeAPIKeyV1() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "wakatime-api-key.1",
		Description: "WakaTime API key version 1 (UUID format).",
		Regex: utils.GenerateSemiGenericRegex(
			[]string{`waka[_. -]?time(?:[_. -]*(?:api))?[_. -]*(?:secret|key|token)`},
			`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`,
			false,
		),
		Keywords:     []string{"wakatime", "waka_time", "waka-time", "waka time", "waka.time"},
		ValidateExpr: wakaTimeAPIKeyValidateExpr,
		Filter:       utils.MinEntropy(3.0),
	}

	// validate
	tps := []string{
		`WAKATIME_API_KEY=a1b2c3d4-e5f6-7890-abcd-ef1234567890`,
		`waka_time_api_key: "d4e5f6a7-b8c9-0123-4567-89abcdef0123"`,
	}
	fps := []string{
		`API_KEY=a1b2c3d4-e5f6-7890-abcd-ef1234567890`,
		`WAKATIME_API_KEY=00000000-0000-0000-0000-000000000000`,
	}
	return utils.Validate(r, tps, fps)
}

func WakaTimeAPIKeyV2() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:       "wakatime-api-key.2",
		Description:  "WakaTime API key version 2 (waka_ format).",
		Regex:        utils.GenerateUniqueTokenRegex(`waka_[a-z0-9]{36,64}`, true),
		Keywords:     []string{"waka_"},
		ValidateExpr: wakaTimeAPIKeyValidateExpr,
		Filter:       utils.MinEntropy(3.0),
	}

	// validate
	tps := []string{
		"WAKATIME_API_KEY=waka_" + secrets.NewSecretWithEntropy(`[a-z0-9]{40}`, 3.0),
	}
	fps := []string{
		`WAKATIME_API_KEY=waka_short`,
		`WAKATIME_API_KEY=waka_0000000000000000000000000000000000000000`,
	}
	return utils.Validate(r, tps, fps)
}
