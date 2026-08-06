package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func TableauPersonalAccessTokenName() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "tableau-personal-access-token-name.1",
		Description: "Tableau personal access-token name, used as a component of the token rule.",
		Regex: utils.GenerateSemiGenericRegex(
			[]string{`tableau(?:[_. -]*(?:personal[_. -]*access|pat))?[_. -]*(?:token[_. -]*)?name`},
			`[A-Za-z][A-Za-z0-9_-]{2,50}`,
			false,
		),
		Keywords:   []string{"tableau"},
		SkipReport: true,
	}

	// validate
	tps := []string{
		`TABLEAU_TOKEN_NAME=test-token-6`,
		`tableau_pat_name="production_service"`,
	}
	fps := []string{
		`TOKEN_NAME=test-token-6`,
		`TABLEAU_TOKEN_NAME=1invalid`,
	}
	return utils.Validate(r, tps, fps)
}

func TableauServerHost() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "tableau-server-host.1",
		Description: "Tableau Online server host, used as a component of the personal access-token rule.",
		Regex:       regexp.MustCompile(`(?i)\b([a-z0-9-]+\.online\.tableau\.com)\b`),
		Keywords:    []string{"online.tableau.com"},
		SkipReport:  true,
	}

	// validate
	tps := []string{
		`TABLEAU_SERVER=https://prod-ansouthgest-a.online.tableau.com`,
	}
	fps := []string{
		`TABLEAU_SERVER=https://prod.tabeau.com`,
		`TABLEAU_SERVER=https://online.tableau.com.evil.example`,
	}
	return utils.Validate(r, tps, fps)
}

func TableauPersonalAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "tableau-personal-access-token.1",
		Description: "Tableau personal access token.",
		Regex:       regexp.MustCompile(`\b([A-Za-z0-9+/]{22}==:[A-Za-z0-9]{32})\b`),
		Keywords:    []string{"tableau"},
		RequiredRules: []*config.Required{
			{RuleID: "tableau-personal-access-token-name.1", WithinLines: utils.Ptr(20)},
			{RuleID: "tableau-server-host.1", WithinLines: utils.Ptr(20)},
		},
		ValidateExpr: `let r = http.post("https://" + captures["tableau-server-host.1"] + "/api/3.26/auth/signin", {
    "Content-Type": "application/json",
    "Accept": "application/json"
  }, "{\"credentials\":{\"personalAccessTokenName\":\"" + captures["tableau-personal-access-token-name.1"]
    + "\",\"personalAccessTokenSecret\":\"" + finding["secret"] + "\",\"site\":{}}}");
  r.status == 200 && (r.json?.credentials?.token ?? "") != "" ? {
    "result": "valid"
  } : r.status in [400, 401, 403] ? {
    "result": "invalid",
    "reason": "Invalid Tableau credentials"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.5),
	}

	// validate
	tps := []string{
		"TABLEAU_PAT_SECRET=" + secrets.NewSecret(`[A-Za-z0-9+/]{22}`) + "==:" + secrets.NewSecretWithEntropy(utils.AlphaNumeric("32"), 3.5),
	}
	fps := []string{
		`TABLEAU_PAT_SECRET=invalid-secret-format`,
		`TOKEN=YMqNfVWiTSa0QgpoJ9GpCw==:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`,
	}
	return utils.Validate(r, tps, fps)
}
