package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "tableau-personal-access-token-name.1",
	Confidence:  "high",
	Description: "Tableau personal access-token name, used as a component of the token rule.",
	Regex: Assignment(
		[]string{`tableau(?:[_. -]*(?:personal[_. -]*access|pat))?[_. -]*(?:token[_. -]*)?name`},
		`[A-Za-z][A-Za-z0-9_-]{2,50}`,
	),
	Keywords:   []string{"tableau"},
	SkipReport: true,
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Mode:  "match",
			Input: "TABLEAU_TOKEN_NAME=test-token-6",
			Expect: []config.ExpectedFinding{
				{Secret: "test-token-6"},
			},
		},
		{
			Name:  "true positive 2",
			Mode:  "match",
			Input: `tableau_pat_name="production_service"`,
			Expect: []config.ExpectedFinding{
				{Secret: "production_service"},
			},
		},
		{
			Name:   "false positive 1",
			Mode:   "match",
			Input:  "TOKEN_NAME=test-token-6",
			Expect: []config.ExpectedFinding{},
		},
		{
			Name:   "false positive 2",
			Mode:   "match",
			Input:  "TABLEAU_TOKEN_NAME=1invalid",
			Expect: []config.ExpectedFinding{},
		},
	},
})

var _ = Add(config.Rule{
	ID:          "tableau-server-host.1",
	Confidence:  "high",
	Description: "Tableau Online server host, used as a component of the personal access-token rule.",
	Regex:       `(?i)\b([a-z0-9-]+\.online\.tableau\.com)\b`,
	Keywords:    []string{"online.tableau.com"},
	SkipReport:  true,
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Mode:  "match",
			Input: "TABLEAU_SERVER=https://prod-ansouthgest-a.online.tableau.com",
			Expect: []config.ExpectedFinding{
				{Secret: "prod-ansouthgest-a.online.tableau.com"},
			},
		},
		{
			Name:   "false positive 1",
			Mode:   "match",
			Input:  "TABLEAU_SERVER=https://prod.tabeau.com",
			Expect: []config.ExpectedFinding{},
		},
		{
			Name:   "false positive 2",
			Mode:   "match",
			Input:  "TABLEAU_SERVER=https://online.tableau.com.evil.example",
			Expect: []config.ExpectedFinding{},
		},
	},
})

var _ = Add(config.Rule{
	ID:          "tableau-personal-access-token.1",
	Confidence:  "high",
	Description: "Tableau personal access token.",
	Regex:       `(?:^|[^A-Za-z0-9+/])([A-Za-z0-9+/]{22}==:[A-Za-z0-9]{32})\b`,
	Keywords:    []string{"tableau"},
	Components: []config.Component{
		{RuleID: "tableau-personal-access-token-name.1", Within: "20L"},
		{RuleID: "tableau-server-host.1", Within: "20L"},
	},
	ValidateExpr: `let r = http.post("https://" + (components["tableau-server-host.1"]?.secret ?? "") + "/api/3.26/auth/signin", {
    "Content-Type": "application/json",
    "Accept": "application/json"
  }, "{\"credentials\":{\"personalAccessTokenName\":\"" + (components["tableau-personal-access-token-name.1"]?.secret ?? "")
    + "\",\"personalAccessTokenSecret\":\"" + finding["secret"] + "\",\"site\":{}}}");
  r.status == 200 && (r.json?.credentials?.token ?? "") != "" ? {
    "result": "valid"
  } : r.status in [400, 401, 403] ? {
    "result": "invalid",
    "reason": "Invalid Tableau credentials"
  } : validate.unknown(r)`,
	FilterExpr: MinEntropy(3.5),
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Input: "TABLEAU_PAT_SECRET=YMqNfVWiTSa0QgpoJ9GpCw==:0123456789abcdefghijklmnopqrstuv\nTABLEAU_TOKEN_NAME=test-token-6\nTABLEAU_SERVER=https://prod-ansouthgest-a.online.tableau.com",
			Expect: []config.ExpectedFinding{
				{Secret: "YMqNfVWiTSa0QgpoJ9GpCw==:0123456789abcdefghijklmnopqrstuv", ComponentSets: []map[string]string{{"tableau-personal-access-token-name.1": "test-token-6", "tableau-server-host.1": "prod-ansouthgest-a.online.tableau.com"}}},
			},
		},
		{
			Name:  "true positive 2",
			Input: "TABLEAU_PAT_SECRET=/MqNfVWiTSa0QgpoJ9GpCw==:0123456789abcdefghijklmnopqrstuv\nTABLEAU_TOKEN_NAME=test-token-6\nTABLEAU_SERVER=https://prod-ansouthgest-a.online.tableau.com",
			Expect: []config.ExpectedFinding{
				{Secret: "/MqNfVWiTSa0QgpoJ9GpCw==:0123456789abcdefghijklmnopqrstuv", ComponentSets: []map[string]string{{"tableau-personal-access-token-name.1": "test-token-6", "tableau-server-host.1": "prod-ansouthgest-a.online.tableau.com"}}},
			},
		},
		{
			Name:  "true positive 3",
			Input: "TABLEAU_PAT_SECRET=+MqNfVWiTSa0QgpoJ9GpCw==:0123456789abcdefghijklmnopqrstuv\nTABLEAU_TOKEN_NAME=test-token-6\nTABLEAU_SERVER=https://prod-ansouthgest-a.online.tableau.com",
			Expect: []config.ExpectedFinding{
				{Secret: "+MqNfVWiTSa0QgpoJ9GpCw==:0123456789abcdefghijklmnopqrstuv", ComponentSets: []map[string]string{{"tableau-personal-access-token-name.1": "test-token-6", "tableau-server-host.1": "prod-ansouthgest-a.online.tableau.com"}}},
			},
		},
		NoMatch("false positive 1", "TABLEAU_PAT_SECRET=invalid-secret-format"),
		NoMatch("false positive 2", "TABLEAU_PAT_SECRET=AYMqNfVWiTSa0QgpoJ9GpCw==:0123456789abcdefghijklmnopqrstuv"),
		NoMatch("false positive 3", "TABLEAU_PAT_SECRET=YMqNfVWiTSa0QgpoJ9GpCw==:0123456789abcdefghijklmnopqrstuvw"),
		NoMatch("false positive 4", "TOKEN=YMqNfVWiTSa0QgpoJ9GpCw==:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
	},
})
