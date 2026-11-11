package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "lark-app-id",
	Confidence:  "high",
	Description: "Lark application ID, used as a component of the Lark application-secret rule.",
	Regex:       `\b(cli_[A-Za-z0-9]{16})`,
	Keywords:    []string{"cli_"},
	SkipReport:  true,
	FilterExpr:  `entropy(finding["secret"]) < 3.0 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Mode:  "match",
			Input: "LARK_APP_ID=cli_AbCdEfGhIjKlMnOp",
			Expect: []config.ExpectedFinding{
				{Secret: "cli_AbCdEfGhIjKlMnOp"},
			},
		},
		{
			Name:   "false positive 1",
			Mode:   "match",
			Input:  "LARK_APP_ID=cli_short",
			Expect: []config.ExpectedFinding{},
		},
	},
})

var _ = Add(config.Rule{
	ID:          "lark-app-secret",
	Confidence:  "high",
	Description: "Lark application secret.",
	Regex: Assignment(
		[]string{"lark", "larksuite"},
		`(?i)[A-Za-z0-9]{32}`,
	),
	Keywords: []string{"lark"},
	Components: []config.Component{
		{RuleID: "lark-app-id"},
	},
	ValidateExpr: `let r = http.post("https://open.larksuite.com/open-apis/auth/v3/tenant_access_token/internal", {
    "Content-Type": "application/json",
    "Accept": "application/json"
  }, "{\"app_id\":" + toJSON((components["lark-app-id"]?.secret ?? "")) + ",\"app_secret\":" + toJSON(finding["secret"]) + "}");
let code = r.json?.code ?? -1;
r.status == 200 && code == 0 ? {
    "result": "valid"
  } : r.status == 200 && code in [10003, 10005, 10014, 10015] ? {
    "result": "invalid",
    "reason": (r.json?.msg ?? "Invalid application credentials")
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Input: "LARK_APP_SECRET=5fbbd6p84oe7ut4qrttebiwar77s63do\nLARK_APP_ID=cli_AbCdEfGhIjKlMnOp",
			Expect: []config.ExpectedFinding{
				{Secret: "5fbbd6p84oe7ut4qrttebiwar77s63do", ComponentSets: []map[string]string{{"lark-app-id": "cli_AbCdEfGhIjKlMnOp"}}},
			},
		},
		NoMatch("false positive 1", "LARK_APP_SECRET=short"),
		NoMatch("false positive 2", "OTHER_APP_SECRET=AbCdEfGhIjKlMnOpQrStUvWxYz123456"),
	},
})
