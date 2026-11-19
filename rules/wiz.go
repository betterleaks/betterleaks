package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "wiz-client-id.1",
	Confidence:  "medium",
	Description: "Wiz OAuth client ID, used as a component of the Wiz client-secret composite rule.",
	Regex:       rulebuilder.Assignment([]string{"wiz"}, `[A-Za-z0-9]{53,56}`),
	Keywords:    []string{"wiz"},
	SkipReport:  true,
	FilterExpr:  rulebuilder.MinEntropy(4.0),
	Tests: []config.RuleTest{
		rulebuilder.MatchComponent("true positive 1", "WIZ_CLIENT_ID=RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klKiz9pyKl17ltLSv", "RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klKiz9pyKl17ltLSv"),
		rulebuilder.NoMatchComponent("false positive 1", "CLIENT_ID=RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klKiz9pyKl17ltLSv"),
		rulebuilder.NoMatchComponent("false positive 2", "WIZ_CLIENT_ID=short"),
		rulebuilder.NoMatchComponent("false positive 3", "WIZ_CLIENT_ID=00000000000000000000000000000000000000000000000000000000"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "wiz-client-secret.1",
	Confidence:  "high",
	Description: "Wiz OAuth client secret, which may allow access to the Wiz API when paired with its client ID.",
	Regex:       rulebuilder.Assignment([]string{"wiz"}, `[A-Za-z0-9]{64}`),
	Keywords:    []string{"wiz"},
	Components: []config.Component{
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
	FilterExpr: rulebuilder.MinEntropy(4.0),
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Input: "WIZ_CLIENT_SECRET=RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klKiz9pyKl17ltLSvQmntzYlk\nWIZ_CLIENT_ID=RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klKiz9pyKl17ltLSv",
			Expect: []config.ExpectedFinding{
				{Secret: "RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klKiz9pyKl17ltLSvQmntzYlk", ComponentSets: []map[string]string{{"wiz-client-id.1": "RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klKiz9pyKl17ltLSv"}}},
			},
		},
		rulebuilder.NoMatch("false positive 1", "CLIENT_SECRET=RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klKiz9pyKl17ltLSvQmntzYlk"),
		rulebuilder.NoMatch("false positive 2", "WIZ_CLIENT_SECRET=short"),
		rulebuilder.NoMatch("false positive 3", "WIZ_CLIENT_SECRET=0000000000000000000000000000000000000000000000000000000000000000"),
	},
})
