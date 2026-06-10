package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func SupabaseManagementToken() *config.Rule {
	r := config.Rule{
		RuleID:      "supabase-management-token",
		Description: "Detected a Supabase Management Token, which may allow unauthorized access to Supabase organizations and projects.",
		Regex:       utils.GenerateUniqueTokenRegex(`sbp_[a-z0-9_-]{40}`, false),
		Keywords:    []string{"sbp_"},
		ValidateCEL: `cel.bind(r,
  http.get("https://api.supabase.com/v1/organizations", {
    "Authorization": "Bearer " + finding["secret"]
  }),
  r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)
)`,
		Filter: `entropy(finding["secret"]) <= 3.5
|| !matchesAny(finding["secret"], [r"""^sbp_[a-z0-9_-]*[0-9][a-z0-9_-]*[0-9][a-z0-9_-]*$"""])`,
	}

	tps := []string{
		`supabase_management_token = "sbp_abcd1234efgh5678ijkl9012mnop3456qrst7890"`,
		`SUPABASE_ACCESS_TOKEN=sbp_1234567890abcdefghij1234567890klmnopqrst`,
	}
	fps := []string{
		`supabase_management_token = "sbp_abcdefghijklmnopqrstuvwxyzabcdefghijklmn"`,
		`SUPABASE_ACCESS_TOKEN=sbp_1234567890abcdefghij1234567890klmnopqrs`,
	}
	return utils.Validate(r, tps, fps)
}

func SupabaseProjectAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "supabase-project-api-key",
		Description: "Detected a Supabase Project API Key, which may expose project data through Supabase APIs when paired with a project URL.",
		Regex:       utils.GenerateUniqueTokenRegex(`sb_secret_[A-Za-z0-9_-]{31}`, false),
		Keywords:    []string{"sb_secret_"},
		RequiredRules: []*config.Required{
			{RuleID: "supabase-project-url"},
		},
		ValidateCEL: `cel.bind(r,
  http.get(captures["supabase-project-url"] + "/rest/v1/?select=*", {
    "Apikey": finding["secret"],
    "User-Agent": ""
  }),
  r.status == 200 && r.body.contains("\"host\":") ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)
)`,
		Filter: `entropy(finding["secret"]) <= 4.0`,
	}

	tps := []string{
		`SUPABASE_SERVICE_ROLE_KEY="sb_secret_9uM4GhB0STF5R4K3HxQtlg_bzWW6DRj"`,
		`supabase_api_key: sb_secret_szE_jsbktD3pWgnfUjgahw_hcHEIOBH`,
	}
	fps := []string{
		`SUPABASE_SERVICE_ROLE_KEY="sb_secret_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`,
		`supabase_api_key: sb_secret_9uM4GhB0STF5R4K3HxQtlg_bzWW6DR`,
	}
	return utils.Validate(r, tps, fps)
}

func SupabaseProjectURL() *config.Rule {
	r := config.Rule{
		RuleID:      "supabase-project-url",
		Description: "Detected a Supabase project URL, used as a component of the supabase-project-api-key composite rule.",
		Regex:       regexp.MustCompile(`\b(https://[a-z0-9]{16,32}\.supabase\.co)\b`),
		Keywords:    []string{"supabase.co"},
		SkipReport:  true,
		Filter:      `entropy(finding["secret"]) <= 3.0`,
	}

	tps := []string{
		`NEXT_PUBLIC_SUPABASE_URL="https://ejcvydfyxzmbtfbfstnq.supabase.co"`,
		`supabaseUrl: "https://abcdefghijklmnop.supabase.co"`,
	}
	fps := []string{
		`NEXT_PUBLIC_SUPABASE_URL="http://ejcvydfyxzmbtfbfstnq.supabase.co"`,
		`supabaseUrl: "https://short.supabase.co"`,
	}
	return utils.Validate(r, tps, fps)
}
