package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func NgrokAPIKey() *config.Rule {
	// Current ngrok API keys and agent authtokens share this family. Passing an
	// agent token to the API returns ERR_NGROK_206, which proves the credential
	// is live without opening a tunnel or mutating account state.
	r := config.Rule{
		RuleID:      "ngrok-api-key.1",
		Confidence:  "high",
		Description: "ngrok API key or agent authtoken, which may allow tunnel access or account administration.",
		Regex: utils.GenerateSemiGenericRegex(
			[]string{`ngrok[_. -]*(?:(?:api|agent)[_. -]*)?(?:secret|key|token|authtoken)`},
			`2[A-Za-z0-9]{26}_[0-9][A-Za-z0-9]{20}`,
			false,
		),
		Keywords: []string{"ngrok"},
		ValidateExpr: `let r = http.get("https://api.ngrok.com/agent_ingresses", {
    "Authorization": "Bearer " + finding["secret"],
    "ngrok-version": "2",
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status == 400 && (r.body contains "ERR_NGROK_206") ? {
    "result": "valid",
    "reason": "Live ngrok agent authtoken"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Authentication failed"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.5),
	}

	key := "2" +
		secrets.NewSecretWithEntropy(`[A-Za-z0-9]{26}`, 3.5) + "_" +
		secrets.NewSecret(`[0-9]`) +
		secrets.NewSecretWithEntropy(`[A-Za-z0-9]{20}`, 3.5)
	tps := []string{
		`NGROK_AUTHTOKEN=` + key,
		`ngrok api key: "` + key + `"`,
	}
	fps := []string{
		`AUTHTOKEN=` + key,
		`NGROK_AUTHTOKEN=2short_1short`,
		`NGROK_AUTHTOKEN=200000000000000000000000000_100000000000000000000`,
	}
	return utils.Validate(r, tps, fps)
}
