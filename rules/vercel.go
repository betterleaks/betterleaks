package rules

import "github.com/betterleaks/betterleaks/v2/config"

const vercelTokenValidateExpr = `let r = http.get("https://api.vercel.com/v2/user", {
  "Authorization": "Bearer " + finding["secret"]
}); r.status == 200 && (r.json?.user?.id ?? "") != "" ? {
  "result": "valid",
  "analysis": {
    "user_id": r.json?.user?.id ?? "",
    "email": r.json?.user?.email ?? "",
    "username": r.json?.user?.username ?? "",
    "name": r.json?.user?.name ?? ""
  }
} : r.status in [401, 403] ? {
  "result": "invalid",
  "reason": "Unauthorized"
} : validate.unknown(r)`

// User/team scopes identify account boundaries, not effective resource grants.
// One additional GET enriches the cached owner identity without enumerating tokens.
// https://vercel.com/docs/rest-api/authentication/get-auth-token-metadata
const vercelTokenAnalyzeExpr = `let input = validation.analysis;
let r = http.get("https://api.vercel.com/v5/user/tokens/current", {
  "Authorization": "Bearer " + finding["secret"],
  "Accept": "application/json"
});
let details_ok = r.status == 200 && (r.json?.token?.id ?? "") != "";
let token = details_ok ? (r.json?.token ?? {}) : {};
let scopes = token["scopes"] ?? [];
{
  "reason": !details_ok ? "Vercel token metadata could not be retrieved" :
    len(scopes) == 0 ? "Vercel did not return token scope metadata" :
    "Vercel token scopes do not establish resource permissions",
  "identity": {
    "id": input["user_id"] ?? "",
    "email": input["email"] ?? "",
    "username": input["username"] ?? "",
    "name": input["name"] ?? "",
    "account": len(scopes) == 1 && (scopes[0]?.type ?? "") == "team" ? {
      "id": scopes[0]?.teamId ?? ""
    } : {}
  },
  "metadata": {
    "token_id": token["id"] ?? "",
    "token_name": token["name"] ?? "",
    "token_type": token["type"] ?? "",
    "scopes": map(scopes, {{
      "type": #.type ?? "",
      "team_id": #.teamId ?? "",
      "created_at": #.createdAt ?? nil,
      "expires_at": #.expiresAt ?? nil
    }}),
    "created_at": token["createdAt"] ?? nil,
    "expires_at": token["expiresAt"] ?? nil
  },
  "capabilities": []
}`

var _ = Add(config.Rule{
	ID:           "vercel-api-token",
	Confidence:   "high",
	Description:  "Detected a Vercel API Token, which may expose deployment and serverless infrastructure to unauthorized access.",
	Regex:        Assignment([]string{"vercel"}, `(?i)[A-Z0-9]{24}`),
	Keywords:     []string{"vercel"},
	ValidateExpr: vercelTokenValidateExpr,
	AnalyzeExpr:  vercelTokenAnalyzeExpr,
	FilterExpr:   `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("vercel assignment", `vercelToken = "5FBBD6P84OE7UT4QRTTEBIWA"`, "5FBBD6P84OE7UT4QRTTEBIWA"),
		Match("true positive 1", "vercel-key = DdZV6ZDZW6Vpl7n7JqtrCE5i", "DdZV6ZDZW6Vpl7n7JqtrCE5i"),
		Match("true positive 2", "vercel_token = zyMBA1qVEMAf4UNNZtCAbg6u", "zyMBA1qVEMAf4UNNZtCAbg6u"),
		Match("true positive 3", "vercel_api_key = MTg0AW799OY1HmyDdn84or3C", "MTg0AW799OY1HmyDdn84or3C"),
		Match("true positive 4", "vercel_secret = A7n9Xfp3tBz7D0XpOTMWpiOM", "A7n9Xfp3tBz7D0XpOTMWpiOM"),
		NoMatch("Too short", "vercel_key = DdZV6ZDZW6Vpl7n7Jq"),
		NoMatch("All same chars (low entropy)", "vercel_key = AAAAAAAAAAAAAAAAAAAAAAAA"),
	},
})

var _ = Add(config.Rule{
	ID:           "vercel-personal-access-token",
	Confidence:   "high",
	Description:  "Detected a Vercel Personal Access Token (vcp_), which may expose full account and deployment management capabilities.",
	Regex:        Token(`(?i)vcp_[A-Za-z0-9_-]{56}`),
	Keywords:     []string{"vcp_"},
	ValidateExpr: vercelTokenValidateExpr,
	AnalyzeExpr:  vercelTokenAnalyzeExpr,
	FilterExpr:   `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("vercel assignment", `vercelToken = "vcp_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG"`, "vcp_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG"),
		Match("bare secret", "vcp_35UYJwYZDigYATKhxJUAhPqRhit2Xe3dtiG60LsUTHeklEXDQ94Jafpu", "vcp_35UYJwYZDigYATKhxJUAhPqRhit2Xe3dtiG60LsUTHeklEXDQ94Jafpu"),
		Match("true positive 1", "vercel_access_token=vcp_4mcjwVDwqtVCVGWCcxRjdzGpkGZ3NkwXZv8ktcoQ0EG0dnjpMP1Rzi71", "vcp_4mcjwVDwqtVCVGWCcxRjdzGpkGZ3NkwXZv8ktcoQ0EG0dnjpMP1Rzi71"),
		NoMatch("Too short", "vcp_35UYJwYZDigYATKhxJUAhPqRhit2Xe3dtiG60LsUTHe"),
		NoMatch("Wrong prefix", "vct_35UYJwYZDigYATKhxJUAhPqRhit2Xe3dtiG60LsUTHeklEXDQ94Jafpu"),
	},
})

var _ = Add(config.Rule{
	ID:          "vercel-integration-token",
	Confidence:  "high",
	Description: "Detected a Vercel Integration Token (vci_), which may allow third-party service integrations to act on behalf of users.",
	Regex:       Token(`(?i)vci_[A-Za-z0-9_-]{56}`),
	Keywords:    []string{"vci_"},
	ValidateExpr: `let r = http.get("https://api.vercel.com/v2/user", {
    "Authorization": "Bearer " + finding["secret"]
  }); r.status == 200 && (r.body contains "\"user\"") ? {
    "result": "valid",
    "metadata": {"email": (r.json?.user?.email ?? ""), "username": (r.json?.user?.username ?? ""), "user_id": (r.json?.user?.id ?? "")}
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("vercel assignment", `vercelToken = "vci_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG"`, "vci_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG"),
		Match("true positive 1", "Vercel Integration Token: vci_35UYJwYZDigYATKhxJUAhPqRhit2Xe3dtiG60LsUTHeklEXDQ94Jafpu", "vci_35UYJwYZDigYATKhxJUAhPqRhit2Xe3dtiG60LsUTHeklEXDQ94Jafpu"),
		NoMatch("Too short", "vci_35UYJwYZDigYATKhxJUAhPqRhit2Xe3dtiG60LsUTHe"),
		NoMatch("Wrong prefix", "vcp_35UYJwYZDigYATKhxJUAhPqRhit2Xe3dtiG60LsUTHeklEXDQ94Jafpu"),
	},
})

var _ = Add(config.Rule{
	ID:          "vercel-app-access-token",
	Confidence:  "high",
	Description: "Detected a Vercel App Access Token (vca_), which may allow Sign in with Vercel apps to access user resources.",
	Regex:       Token(`(?i)vca_[A-Za-z0-9_-]{56}`),
	Keywords:    []string{"vca_"},
	ValidateExpr: `let r = http.post("https://api.vercel.com/login/oauth/userinfo", {
    "Authorization": "Bearer " + finding["secret"]
  }, ""); r.status == 200 && (r.body contains "\"sub\"") ? {
    "result": "valid",
    "metadata": {"email": (r.json?.email ?? ""), "user_id": (r.json?.sub ?? "")}
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("vercel assignment", `vercelToken = "vca_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG"`, "vca_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG"),
		Match("bare secret", "vca_BQuu9ChDu3n6Pfh6YQnCshpoYkWDSFKogLqmBtQ0tC8NAA5rXt340sjz", "vca_BQuu9ChDu3n6Pfh6YQnCshpoYkWDSFKogLqmBtQ0tC8NAA5rXt340sjz"),
		NoMatch("Too short", "vca_BQuu9ChDu3n6Pfh6YQnCshpoYkWDSFKogLqmBtQ0t"),
		NoMatch("Wrong prefix", "vcb_BQuu9ChDu3n6Pfh6YQnCshpoYkWDSFKogLqmBtQ0tC8NAA5rXt340sjz"),
	},
})

var _ = Add(config.Rule{
	ID:          "vercel-app-refresh-token",
	Confidence:  "high",
	Description: "Detected a Vercel App Refresh Token (vcr_), which may allow persistent unauthorized access through token refresh flows.",
	Regex:       Token(`(?i)vcr_[A-Za-z0-9_-]{56}`),
	Keywords:    []string{"vcr_"},
	ValidateExpr: `let r = http.post("https://api.vercel.com/login/oauth/token/introspect", {
    "Content-Type": "application/x-www-form-urlencoded"
  }, "token=" + finding["secret"]); r.status == 200 && (r.body contains "\"active\":true") ? {
    "result": "valid"
  } : r.status == 200 && (r.body contains "\"active\":false") ? {
    "result": "invalid",
    "reason": "Token inactive"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("vercel assignment", `vercelToken = "vcr_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG"`, "vcr_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG"),
		Match("bare secret", "vcr_BQuu9ChDu3n6Pfh6YQnCshpoYkWDSFKogLqmBtQ0tC8NAA5rXt340sjz", "vcr_BQuu9ChDu3n6Pfh6YQnCshpoYkWDSFKogLqmBtQ0tC8NAA5rXt340sjz"),
		NoMatch("Too short", "vcr_BQuu9ChDu3n6Pfh6YQnCshpoYkWDSFKogLqmBtQ0t"),
		NoMatch("Wrong prefix", "vcp_BQuu9ChDu3n6Pfh6YQnCshpoYkWDSFKogLqmBtQ0tC8NAA5rXt340sjz"),
	},
})

var _ = Add(config.Rule{
	ID:          "vercel-ai-gateway-key",
	Confidence:  "high",
	Description: "Detected a Vercel AI Gateway API Key (vck_), which may expose AI model routing and gateway access to unauthorized parties.",
	Regex:       Token(`(?i)vck_[A-Za-z0-9_-]{56}`),
	Keywords:    []string{"vck_"},
	ValidateExpr: `let r = http.post("https://ai-gateway.vercel.sh/v1/chat/completions", {
    "Authorization": "Bearer " + finding["secret"],
    "Content-Type": "application/json"
  }, "{\"model\":\"openai/gpt-3.5-turbo\",\"messages\":[{\"role\":\"user\",\"content\":\"x\"}],\"max_tokens\":1}"); r.status in [200, 403] ? {
    "result": "valid"
  } : r.status in [401] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("vercel assignment", `vercelToken = "vck_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG"`, "vck_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG"),
		Match("bare secret", "vck_2YkmQj1uHqCVNoUx5a9uvRTe81gmAcln5hoRMPWFBU4tulufUf0OzP2K", "vck_2YkmQj1uHqCVNoUx5a9uvRTe81gmAcln5hoRMPWFBU4tulufUf0OzP2K"),
		NoMatch("Too short", "vck_2YkmQj1uHqCVNoUx5a9uvRTe81gmAcln5hoRMPWFBU4t"),
		NoMatch("Wrong prefix", "vcp_2YkmQj1uHqCVNoUx5a9uvRTe81gmAcln5hoRMPWFBU4tulufUf0OzP2K"),
	},
})
