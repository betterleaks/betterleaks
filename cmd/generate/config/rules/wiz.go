package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

func WizClientID() *config.Rule {
	r := config.Rule{
		RuleID:      "wiz-client-id.1",
		Confidence:  "medium",
		Description: "Wiz OAuth client ID, used as a component of the Wiz client-secret composite rule.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"wiz"}, `[A-Za-z0-9]{53,56}`, false),
		Keywords:    []string{"wiz"},
		SkipReport:  true,
		Filter:      utils.MinEntropy(4.0),
	}

	clientID := secrets.NewSecretWithEntropy(`[A-Za-z0-9]{56}`, 4.0)
	tps := []string{
		`WIZ_CLIENT_ID=` + clientID,
	}
	fps := []string{
		`CLIENT_ID=` + clientID,
		`WIZ_CLIENT_ID=short`,
		`WIZ_CLIENT_ID=00000000000000000000000000000000000000000000000000000000`,
	}
	return utils.Validate(r, tps, fps)
}

func WizClientSecret() *config.Rule {
	r := config.Rule{
		RuleID:      "wiz-client-secret.1",
		Confidence:  "high",
		Description: "Wiz OAuth client secret, which may allow access to the Wiz API when paired with its client ID.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"wiz"}, `[A-Za-z0-9]{64}`, false),
		Keywords:    []string{"wiz"},
		Components: []*config.Component{
			{RuleID: "wiz-client-id.1", Within: "5L"},
		},
		ValidateExpr: `let r = http.post("https://auth.app.wiz.io/oauth/token", {
    "Accept": "application/json",
    "Content-Type": "application/x-www-form-urlencoded"
  }, "grant_type=client_credentials" +
    "&audience=wiz-api" +
    "&client_id=" + strings.urlQueryEscape((components["wiz-client-id.1"]?.secret ?? "")) +
    "&client_secret=" + strings.urlQueryEscape(finding["secret"]));
  r.status == 200 && (r.json?.access_token ?? "") != "" ? {
    "result": "valid"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(4.0),
	}

	clientSecret := secrets.NewSecretWithEntropy(`[A-Za-z0-9]{64}`, 4.0)
	tps := []string{
		`WIZ_CLIENT_SECRET=` + clientSecret,
	}
	fps := []string{
		`CLIENT_SECRET=` + clientSecret,
		`WIZ_CLIENT_SECRET=short`,
		`WIZ_CLIENT_SECRET=0000000000000000000000000000000000000000000000000000000000000000`,
	}
	return utils.Validate(r, tps, fps)
}
