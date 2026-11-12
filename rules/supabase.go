package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "supabase-management-token",
	Confidence:  "high",
	Description: "Detected a Supabase Management Token, which may allow unauthorized access to Supabase organizations and projects.",
	Regex:       rulebuilder.Token(`sbp_[a-z0-9_-]{40}`),
	Keywords:    []string{"sbp_"},
	ValidateExpr: `let r = http.get("https://api.supabase.com/v1/organizations", {
    "Authorization": "Bearer " + finding["secret"]
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: "entropy(finding[\"secret\"]) <= 3.5\n|| !matchesAny(finding[\"secret\"], [`^sbp_[a-z0-9_-]*[0-9][a-z0-9_-]*[0-9][a-z0-9_-]*$`])",
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", `supabase_management_token = "sbp_abcd1234efgh5678ijkl9012mnop3456qrst7890"`, "sbp_abcd1234efgh5678ijkl9012mnop3456qrst7890"),
		rulebuilder.Match("true positive 2", "SUPABASE_ACCESS_TOKEN=sbp_1234567890abcdefghij1234567890klmnopqrst", "sbp_1234567890abcdefghij1234567890klmnopqrst"),
		rulebuilder.NoMatch("false positive 1", `supabase_management_token = "sbp_abcdefghijklmnopqrstuvwxyzabcdefghijklmn"`),
		rulebuilder.NoMatch("false positive 2", "SUPABASE_ACCESS_TOKEN=sbp_1234567890abcdefghij1234567890klmnopqrs"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "supabase-project-api-key",
	Confidence:  "high",
	Description: "Detected a Supabase Project API Key, which may expose project data through Supabase APIs when paired with a project URL.",
	Regex:       rulebuilder.Token(`sb_secret_[A-Za-z0-9_-]{31}`),
	Keywords:    []string{"sb_secret_"},
	Components: []config.Component{
		{RuleID: "supabase-project-url"},
	},
	ValidateExpr: `let r = http.get((components["supabase-project-url"]?.secret ?? "") + "/rest/v1/?select=*", {
    "Apikey": finding["secret"],
    "User-Agent": ""
  }); r.status == 200 && (r.body contains "\"host\":") ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) <= 4.0`,
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Input: "SUPABASE_SERVICE_ROLE_KEY=\"sb_secret_9uM4GhB0STF5R4K3HxQtlg_bzWW6DRj\"\nNEXT_PUBLIC_SUPABASE_URL=\"https://ejcvydfyxzmbtfbfstnq.supabase.co\"",
			Expect: []config.ExpectedFinding{
				{Secret: "sb_secret_9uM4GhB0STF5R4K3HxQtlg_bzWW6DRj", ComponentSets: []map[string]string{{"supabase-project-url": "https://ejcvydfyxzmbtfbfstnq.supabase.co"}}},
			},
		},
		{
			Name:  "true positive 2",
			Input: "supabase_api_key: sb_secret_szE_jsbktD3pWgnfUjgahw_hcHEIOBH\nNEXT_PUBLIC_SUPABASE_URL=\"https://ejcvydfyxzmbtfbfstnq.supabase.co\"",
			Expect: []config.ExpectedFinding{
				{Secret: "sb_secret_szE_jsbktD3pWgnfUjgahw_hcHEIOBH", ComponentSets: []map[string]string{{"supabase-project-url": "https://ejcvydfyxzmbtfbfstnq.supabase.co"}}},
			},
		},
		rulebuilder.NoMatch("false positive 1", `SUPABASE_SERVICE_ROLE_KEY="sb_secret_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`),
		rulebuilder.NoMatch("false positive 2", "supabase_api_key: sb_secret_9uM4GhB0STF5R4K3HxQtlg_bzWW6DR"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "supabase-project-url",
	Confidence:  "high",
	Description: "Detected a Supabase project URL, used as a component of the supabase-project-api-key composite rule.",
	Regex:       `\b(https://[a-z0-9]{16,32}\.supabase\.co)\b`,
	Keywords:    []string{"supabase.co"},
	SkipReport:  true,
	FilterExpr:  `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		rulebuilder.MatchComponent("true positive 1", `NEXT_PUBLIC_SUPABASE_URL="https://ejcvydfyxzmbtfbfstnq.supabase.co"`, "https://ejcvydfyxzmbtfbfstnq.supabase.co"),
		rulebuilder.MatchComponent("true positive 2", `supabaseUrl: "https://abcdefghijklmnop.supabase.co"`, "https://abcdefghijklmnop.supabase.co"),
		rulebuilder.NoMatchComponent("false positive 1", `NEXT_PUBLIC_SUPABASE_URL="http://ejcvydfyxzmbtfbfstnq.supabase.co"`),
		rulebuilder.NoMatchComponent("false positive 2", `supabaseUrl: "https://short.supabase.co"`),
	},
})
