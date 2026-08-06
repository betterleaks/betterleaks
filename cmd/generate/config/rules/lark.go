package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func LarkAppID() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "lark-app-id",
		Description: "Lark application ID, used as a component of the Lark application-secret rule.",
		Regex:       regexp.MustCompile(`\b(cli_[A-Za-z0-9]{16})`),
		Keywords:    []string{"cli_"},
		SkipReport:  true,
		Filter:      utils.MinEntropy(2.5),
	}

	// validate
	tps := []string{
		`LARK_APP_ID=cli_AbCdEfGhIjKlMnOp`,
	}
	fps := []string{
		`LARK_APP_ID=cli_short`,
	}
	return utils.Validate(r, tps, fps)
}

func LarkAppSecret() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "lark-app-secret",
		Description: "Lark application secret.",
		Regex: utils.GenerateSemiGenericRegex(
			[]string{"lark", "larksuite"},
			`[A-Za-z0-9]{32}`,
			true,
		),
		Keywords: []string{"lark"},
		RequiredRules: []*config.Required{
			{RuleID: "lark-app-id"},
		},
		ValidateExpr: `let r = http.post("https://open.larksuite.com/open-apis/auth/v3/tenant_access_token/internal", {
    "Content-Type": "application/json",
    "Accept": "application/json"
  }, "{\"app_id\":" + json.string(captures["lark-app-id"]) + ",\"app_secret\":" + json.string(finding["secret"]) + "}");
let code = r.json?.code ?? -1;
r.status == 200 && code == 0 ? {
    "result": "valid"
  } : r.status == 200 && code in [10003, 10005, 10014, 10015] ? {
    "result": "invalid",
    "reason": (r.json?.msg ?? "Invalid application credentials")
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.5),
	}

	// validate
	tps := []string{
		"LARK_APP_SECRET=" + secrets.NewSecretWithEntropy(utils.AlphaNumeric("32"), 3.5),
	}
	fps := []string{
		`LARK_APP_SECRET=short`,
		`OTHER_APP_SECRET=AbCdEfGhIjKlMnOpQrStUvWxYz123456`,
	}
	return utils.Validate(r, tps, fps)
}
