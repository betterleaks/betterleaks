package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func CanvaClientID() *config.Rule {
	r := config.Rule{
		RuleID:      "canva-client-id",
		Description: "Detected a Canva Connect API client ID, used as a component of the canva-client-secret composite rule.",
		Regex:       regexp.MustCompile(`(?i)\b(?:canva|CANVA_CLIENT_ID)(?:.|[\n\r]){0,32}?(?:client[_\s-]*id|app[_\s-]*id)(?:.|[\n\r]){0,16}?\b(OC-[A-Za-z0-9_-]{8,16})\b`),
		Keywords:    []string{"canva"},
		SkipReport:  true,
		Filter:      `filter.entropy(finding["secret"]) < 2.5`,
	}

	tps := []string{
		`canva client id: OC-AZ2dqZiY_lec`,
		`CANVA_CLIENT_ID=OC-FAB12-AbCdEf`,
	}
	fps := []string{
		`client id: OC-AZ2dqZiY_lec`,
		`CANVA_CLIENT_ID=OC-short`,
	}
	return utils.Validate(r, tps, fps)
}

func CanvaClientSecret() *config.Rule {
	r := config.Rule{
		RuleID:      "canva-client-secret",
		Description: "Detected a Canva Connect API client secret, which may allow unauthorized OAuth client authentication when paired with a client ID.",
		Regex:       regexp.MustCompile(`\b(cnvca[a-zA-Z0-9_-]{51})\b`),
		Keywords:    []string{"cnvca"},
		RequiredRules: []*config.Required{
			{RuleID: "canva-client-id"},
		},
		ValidateCEL: `cel.bind(r,
  http.post("https://api.canva.com/rest/v1/oauth/token", {
    "Content-Type": "application/x-www-form-urlencoded",
    "Accept": "application/json"
  },
  "grant_type=authorization_code&client_id=" + captures["canva-client-id"] +
  "&client_secret=" + finding["secret"] +
  "&code_verifier=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~abcdefgh&code=invalid"),
  r.status == 400 && r.body.contains("\"invalid_grant\"") && !r.body.contains("\"invalid_client\"") ? {
    "result": "valid"
  } : r.status in [400, 401, 403] && r.body.contains("\"invalid_client\"") ? {
    "result": "invalid",
    "reason": "Invalid client"
  } : validate.unknown(r)
)`,
		Filter: `filter.entropy(finding["secret"]) < 3.5`,
	}

	tps := []string{
		`CANVA_CLIENT_SECRET=cnvcav3RRFkl36rsXClN3-Dsygjl_oGT1-xMhXV70oxnGi6s811bfada`,
	}
	fps := []string{
		`CANVA_CLIENT_SECRET=cnvcav3RRFkl36rsXClN3-Dsygjl_oGT1-xMhXV70oxnGi6s811bfad`,
	}
	return utils.Validate(r, tps, fps)
}
