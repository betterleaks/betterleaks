package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func PlivoAuthID() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "plivo-auth-id",
		Description: "Plivo Auth ID, used as a component of the Plivo Auth Token composite rule.",
		Regex: utils.GenerateSemiGenericRegex(
			[]string{`plivo(?:[_. -]*(?:auth|account))?[_. -]*(?:id|sid)`},
			`MA[A-Z0-9]{18}`,
			true,
		),
		Keywords:   []string{"plivo"},
		SkipReport: true,
		Filter:     utils.MinEntropy(2.8),
	}

	// validate
	tps := []string{
		"PLIVO_AUTH_ID=MA" + secrets.NewSecretWithEntropy(`[A-Z0-9]{18}`, 2.8),
	}
	fps := []string{
		`ACCOUNT_ID=MABDY4DMVMZESYNGY0NV`,
		`PLIVO_AUTH_ID=MA000000000000000000`,
	}
	return utils.Validate(r, tps, fps)
}

func PlivoAuthToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "plivo-auth-token",
		Description: "Plivo Auth Token.",
		Regex: utils.GenerateSemiGenericRegex(
			[]string{`plivo(?:[_. -]*(?:auth))?[_. -]*(?:secret|token|key)`},
			`[A-Za-z0-9_-]{40}`,
			false,
		),
		Keywords: []string{"plivo"},
		RequiredRules: []*config.Required{
			{RuleID: "plivo-auth-id"},
		},
		ValidateExpr: `let authID = captures["plivo-auth-id"];
let r = http.get("https://api.plivo.com/v1/Account/" + authID + "/", {
  "Authorization": "Basic " + base64.encode(bytes(authID + ":" + finding["secret"])),
  "Accept": "application/json"
}); r.status == 200 ? {
  "result": "valid"
} : r.status == 403 ? {
  "result": "valid",
  "reason": "Authenticated but account access is restricted"
} : r.status == 401 ? {
  "result": "invalid",
  "reason": "Unauthorized"
} : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.5),
	}

	// validate
	tps := []string{
		"PLIVO_AUTH_TOKEN=" + secrets.NewSecretWithEntropy(`[A-Za-z0-9_-]{40}`, 3.5),
	}
	fps := []string{
		`AUTH_TOKEN=qFj32Da8vf-g_-8qLu9P_k8XPyAHGrvKrzGTQIN4`,
		`PLIVO_AUTH_TOKEN=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`,
	}
	return utils.Validate(r, tps, fps)
}
