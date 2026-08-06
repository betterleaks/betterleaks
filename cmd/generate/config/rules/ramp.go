package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func RampClientID() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "ramp-client-id",
		Description: "Ramp client ID, used as a component of the Ramp client-secret composite rule.",
		Regex:       utils.GenerateUniqueTokenRegex(`ramp_id_[A-Za-z0-9]{40}`, false),
		Keywords:    []string{"ramp_id_"},
		SkipReport:  true,
		Filter:      utils.MinEntropy(3.0),
	}

	// validate
	tps := []string{
		"RAMP_CLIENT_ID=ramp_id_" + secrets.NewSecretWithEntropy(`[A-Za-z0-9]{40}`, 3.0),
	}
	fps := []string{
		`RAMP_CLIENT_ID=ramp_id_short`,
		`RAMP_CLIENT_ID=ramp_id_0000000000000000000000000000000000000000`,
	}
	return utils.Validate(r, tps, fps)
}

func RampClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "ramp-client-secret",
		Description: "Ramp OAuth client secret.",
		Regex:       utils.GenerateUniqueTokenRegex(`ramp_sec_[A-Za-z0-9]{48}`, false),
		Keywords:    []string{"ramp_sec_"},
		RequiredRules: []*config.Required{
			{RuleID: "ramp-client-id"},
		},
		ValidateExpr: `let r = http.post("https://api.ramp.com/developer/v1/token", {
    "Authorization": "Basic " + base64.encode(bytes(captures["ramp-client-id"] + ":" + finding["secret"])),
    "Content-Type": "application/x-www-form-urlencoded",
    "Accept": "application/json"
  }, "grant_type=client_credentials&scope=betterleaks%3Avalidate"); r.status == 200
    && (r.json?.access_token ?? "") != "" ? {
    "result": "valid"
  } : r.status == 400
    && (r.json?.error ?? "") in ["invalid_scope", "unauthorized_client"] ? {
    "result": "valid"
  } : r.status == 401 && (r.json?.error_v2?.error_code ?? "") == "5001" ? {
    "result": "invalid",
    "reason": "Invalid client credentials"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.5),
	}

	// validate
	tps := []string{
		"RAMP_CLIENT_SECRET=ramp_sec_" + secrets.NewSecretWithEntropy(`[A-Za-z0-9]{48}`, 3.5),
	}
	fps := []string{
		`RAMP_CLIENT_SECRET=ramp_sec_short`,
		`RAMP_CLIENT_SECRET=ramp_sec_000000000000000000000000000000000000000000000000`,
	}
	return utils.Validate(r, tps, fps)
}
