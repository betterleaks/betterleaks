package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func AikidoClientID() *config.Rule {
	r := config.Rule{
		RuleID:      "aikido-client-id",
		Description: "Detected an Aikido client ID, used as a component of the aikido-client-secret composite rule.",
		Regex:       utils.GenerateUniqueTokenRegex(`AIK_CLIENT_[A-Za-z0-9]{24}`, false),
		Keywords:    []string{"AIK_CLIENT_"},
		SkipReport:  true,
		Filter:      `filter.entropy(finding["secret"]) < 3.0`,
	}

	tps := []string{
		`AIK_CLIENT_ID=AIK_CLIENT_a1B2c3D4e5F6g7H8i9J0k1L2`,
	}
	fps := []string{
		`AIK_CLIENT_ID=AIK_CLIENT_a1B2c3D4e5F6g7H8i9J0k1`,
	}
	return utils.Validate(r, tps, fps)
}

func AikidoClientSecret() *config.Rule {
	r := config.Rule{
		RuleID:      "aikido-client-secret",
		Description: "Detected an Aikido client secret, which may allow unauthorized access to Aikido APIs when paired with a client ID.",
		Regex:       utils.GenerateUniqueTokenRegex(`AIK_SECRET_[A-Za-z0-9]{64}`, false),
		Keywords:    []string{"AIK_SECRET_"},
		RequiredRules: []*config.Required{
			{RuleID: "aikido-client-id"},
		},
		ValidateCEL: `cel.bind(r,
  http.post("https://app.aikido.dev/api/oauth/token", {
    "Accept": "application/json",
    "Content-Type": "application/x-www-form-urlencoded",
    "Authorization": "Basic " + base64.encode(bytes(captures["aikido-client-id"] + ":" + finding["secret"]))
  }, "grant_type=client_credentials"),
  r.status == 200 && r.body.contains("\"access_token\"") && r.body.contains("\"token_type\"") ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)
)`,
		Filter: `filter.entropy(finding["secret"]) < 3.5`,
	}

	tps := []string{
		`AIK_CLIENT_SECRET=AIK_SECRET_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1V2w3X4y5Z6a7B8c9D0e1F2`,
	}
	fps := []string{
		`AIK_CLIENT_SECRET=AIK_SECRET_a1B2c3D4e5F6g7H8i9J0k1L2`,
	}
	return utils.Validate(r, tps, fps)
}

func AikidoCIToken() *config.Rule {
	r := config.Rule{
		RuleID:      "aikido-ci-token",
		Description: "Detected an Aikido CI token, which may allow unauthorized CI scan integration activity in Aikido.",
		Regex:       regexp.MustCompile(`\b(AIK_CI_[A-Za-z0-9]{20,44})\b`),
		Keywords:    []string{"AIK_CI_"},
		ValidateCEL: `cel.bind(r,
  http.post("https://app.aikido.dev/api/integrations/ci/scan/start", {
    "X-AIK-API-SECRET": finding["secret"],
    "Content-Type": "application/json"
  }, "{}"),
  r.status in [200, 400, 403] && !r.body.contains("\"Unauthorized\"") ? {
    "result": "valid"
  } : r.status in [401, 403] || r.body.contains("\"Unauthorized\"") ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)
)`,
		Filter: `filter.entropy(finding["secret"]) < 3.0`,
	}

	tps := []string{
		`AIKIDO_TOKEN=AIK_CI_a1B2c3D4e5F6g7H8i9J0k1L2`,
	}
	fps := []string{
		`AIKIDO_TOKEN=AIK_CI_short`,
	}
	return utils.Validate(r, tps, fps)
}
