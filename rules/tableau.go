package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

// https://help.tableau.com/current/api/rest_api/en-us/REST/rest_api_ref_authentication.htm#sign_in
// Cloud requires an existing site's content URL; it has no default-site fallback.
// The site is explicit configuration, not an identity inferred from the hostname.
const tableauValidateExpr = `let contentURL = env.getOrDefault("TABLEAU_SITE_CONTENT_URL", "");
let r = contentURL == "" ? {} : http.post("https://" + (components["tableau-server-host.1"]?.secret ?? "") + "/api/3.26/auth/signin", {
  "Content-Type": "application/json", "Accept": "application/json"
}, toJSON({"credentials": {
  "personalAccessTokenName": components["tableau-personal-access-token-name.1"]?.secret ?? "",
  "personalAccessTokenSecret": finding["secret"], "site": {"contentUrl": contentURL}
}}));
let body = type(r?.json) == "map" ? r.json : {};
let credentials = type(body?.credentials) == "map" ? body.credentials : {};
let user = type(credentials?.user) == "map" ? credentials.user : {};
let site = type(credentials?.site) == "map" ? credentials.site : {};
contentURL == "" ? {
  "result": "needs_validation", "reason": "Tableau Cloud requires TABLEAU_SITE_CONTENT_URL; set it and allowlist it with --provider-env-vars"
} : r.status == 200 && (type(credentials?.token) == "string" && credentials.token != "") ? {
  "result": "valid", "analysis": {
    "id": type(user?.id) == "string" ? user?.id : "",
    "site_id": type(site?.id) == "string" ? site?.id : "",
    "site_content_url": type(site?.contentUrl) == "string" ? site?.contentUrl : ""
  }
} : validate.unknown(r)`
const tableauAnalyzeExpr = `let input = validation.analysis;
{
  "identity": {
    "id": input["id"] ?? "",
    "account": {"id": input["site_id"] ?? ""}
  },
  "capabilities": [],
  "metadata": fromPairs(filter(toPairs({
    "site_content_url": input["site_content_url"] ?? ""
  }), {#[1] != nil && #[1] != "" && #[1] != []}))
}`

var _ = rulebuilder.Add(config.Rule{
	ID:          "tableau-personal-access-token-name.1",
	Confidence:  "high",
	Description: "Tableau personal access-token name, used as a component of the token rule.",
	Regex: rulebuilder.Assignment(
		[]string{`tableau(?:[_. -]*(?:personal[_. -]*access|pat))?[_. -]*(?:token[_. -]*)?name`},
		`[A-Za-z][A-Za-z0-9_-]{2,50}`,
	),
	Keywords:   []string{"tableau"},
	SkipReport: true,
	Tests: []config.RuleTest{
		rulebuilder.MatchComponent("true positive 1", "TABLEAU_TOKEN_NAME=test-token-6", "test-token-6"),
		rulebuilder.MatchComponent("true positive 2", `tableau_pat_name="production_service"`, "production_service"),
		rulebuilder.NoMatchComponent("false positive 1", "TOKEN_NAME=test-token-6"),
		rulebuilder.NoMatchComponent("false positive 2", "TABLEAU_TOKEN_NAME=1invalid"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "tableau-server-host.1",
	Confidence:  "high",
	Description: "Tableau Online server host, used as a component of the personal access-token rule.",
	Regex:       `(?i)\b([a-z0-9-]+\.online\.tableau\.com)\b`,
	Keywords:    []string{"online.tableau.com"},
	SkipReport:  true,
	Tests: []config.RuleTest{
		rulebuilder.MatchComponent("true positive 1", "TABLEAU_SERVER=https://prod-ansouthgest-a.online.tableau.com", "prod-ansouthgest-a.online.tableau.com"),
		rulebuilder.NoMatchComponent("false positive 1", "TABLEAU_SERVER=https://prod.tabeau.com"),
		rulebuilder.NoMatchComponent("false positive 2", "TABLEAU_SERVER=https://online.tableau.com.evil.example"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "tableau-personal-access-token.1",
	Confidence:  "high",
	Description: "Tableau personal access token.",
	Regex:       `(?:^|[^A-Za-z0-9+/])([A-Za-z0-9+/]{22}==:[A-Za-z0-9]{32})\b`,
	Keywords:    []string{"tableau"},
	Components: []config.Component{
		{RuleID: "tableau-personal-access-token-name.1", Within: "20L"},
		{RuleID: "tableau-server-host.1", Within: "20L"},
	},
	ValidateExpr: tableauValidateExpr,
	FilterExpr:   rulebuilder.MinEntropy(3.5),
	AnalyzeExpr:  tableauAnalyzeExpr,
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
		rulebuilder.NoMatch("false positive 1", "TABLEAU_PAT_SECRET=invalid-secret-format"),
		rulebuilder.NoMatch("false positive 2", "TABLEAU_PAT_SECRET=AYMqNfVWiTSa0QgpoJ9GpCw==:0123456789abcdefghijklmnopqrstuv"),
		rulebuilder.NoMatch("false positive 3", "TABLEAU_PAT_SECRET=YMqNfVWiTSa0QgpoJ9GpCw==:0123456789abcdefghijklmnopqrstuvw"),
		rulebuilder.NoMatch("false positive 4", "TOKEN=YMqNfVWiTSa0QgpoJ9GpCw==:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
	},
})
