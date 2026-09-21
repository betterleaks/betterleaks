package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

// https://developers.miro.com/reference/get-access-token-context
// https://developers.miro.com/reference/scopes
// Web SDK-only scopes do not establish REST API grants.
const miroValidateExpr = `let r = http.get("https://api.miro.com/v1/oauth-token", {
  "Authorization": "Bearer " + finding["secret"],
  "Accept": "application/json"
});
r.status == 200 && type(r.json) == "map" && type(r.json?.user) == "map" && (r.json?.user?.id ?? "") != "" ? {
  "result": "valid",
  "analysis": {
    "user_id": string(r.json?.user?.id ?? ""),
    "user_name": string(r.json?.user?.name ?? ""),
    "team_id": string(r.json?.team?.id ?? ""),
    "team_name": string(r.json?.team?.name ?? ""),
    "organization_id": string(r.json?.organization?.id ?? ""),
    "organization_name": string(r.json?.organization?.name ?? ""),
    "scopes": type(r.json?.scopes) == "array" ? filter(r.json.scopes, {type(#) == "string"}) : []
  }
} : r.status in [400, 401] ? {"result": "invalid", "reason": "Unauthorized"} : validate.unknown(r)`

const miroAnalyzeExpr = `let input = validation.analysis;
let scopes = input["scopes"] ?? [];
let capabilities = analysis.capabilities({
  "read": any(scopes, {# in ["boards:read", "projects:read", "auditlogs:read", "organizations:read", "organizations:teams:read", "organizations:groups:read", "contentlogs:export", "boards:export", "organizations:cases:management"]}),
  "write": any(scopes, {# in ["boards:write", "projects:write", "organizations:teams:write", "organizations:groups:write"]}),
  "manage_users": any(scopes, {# in ["organizations:teams:write", "organizations:groups:write", "sessions:delete"]})
});
{
  "identity": {
    "id": input["user_id"] ?? "",
    "name": input["user_name"] ?? "",
    "account": (input["organization_id"] ?? "") != "" ? {
      "id": input["organization_id"], "name": input["organization_name"] ?? ""
    } : {"id": input["team_id"] ?? "", "name": input["team_name"] ?? ""}
  },
  "metadata": {"scopes": scopes},
  "capabilities": capabilities,
  "reason": len(capabilities) == 0 ? "Miro returned no recognized REST API permission grants" : ""
}`

func MiroAccessToken() *config.Rule {
	r := config.Rule{
		ID:           "miro-access-token",
		Confidence:   "high",
		Description:  "Detected a Miro OAuth access token, which may allow unauthorized access to Miro users, teams, boards, and content.",
		Regex:        utils.GenerateUniqueTokenRegex(`eyJtaXJv[A-Za-z0-9-]{10,64}_[A-Za-z0-9_-]{20,64}`, false),
		Keywords:     []string{"miro"},
		ValidateExpr: miroValidateExpr,
		AnalyzeExpr:  miroAnalyzeExpr,
		Filter:       utils.MinEntropy(3.5),
	}

	token := "eyJtaXJv" +
		secrets.NewSecretWithEntropy(`[A-Za-z0-9-]{24}`, 3.5) + "_" +
		secrets.NewSecretWithEntropy(`[A-Za-z0-9_-]{32}`, 3.5)
	tps := utils.GenerateSampleSecrets("miro", token)
	tps = append(tps, `Miro Authorization: Bearer `+token)
	fps := []string{
		`ACCESS_TOKEN=eyJtaXJvLm9yaWdpbiI6ImV1MDEifQ_o-P91OccaII0A63CDSK--x21xiI`,
		`MIRO_TOKEN=eyJtaXJv_short`,
	}
	return utils.Validate(r, tps, fps)
}

func MiroClientID() *config.Rule {
	r := config.Rule{
		ID:          "miro-client-id",
		Confidence:  "medium",
		Description: "Detected a Miro OAuth client ID, used as a component of the miro-client-secret composite rule.",
		Regex:       utils.GenerateSemiGenericRegex([]string{`miro[_. -]*client[_. -]*id`}, utils.Numeric("15,21"), true),
		Keywords:    []string{"miro"},
		SkipReport:  true,
		Filter:      utils.MinEntropy(2.5),
	}

	clientID := secrets.NewSecretWithEntropy(`[0-9]{19}`, 2.5)
	tps := utils.GenerateSampleSecrets("miro_client_id", clientID)
	tps = append(tps, `MIRO_CLIENT_ID=`+clientID)
	fps := []string{
		`CLIENT_ID=3458764668142796369`,
		`MIRO_CLIENT_ID=34587646681427`,
		`MIRO_TEAM_ID=3458764668142796369`,
	}
	return utils.Validate(r, tps, fps)
}

func MiroClientSecret() *config.Rule {
	// Miro validates client credentials before looking up a refresh token. A
	// recognized client pair reaches the invalid-refresh-token response, while a
	// mismatched client ID or secret is rejected as a client credential error.
	r := config.Rule{
		ID:          "miro-client-secret",
		Confidence:  "high",
		Description: "Detected a Miro OAuth client secret, which may allow unauthorized OAuth client authentication when paired with a client ID.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"miro"}, utils.AlphaNumeric("32"), true),
		Keywords:    []string{"miro"},
		Components: []config.Component{
			{RuleID: "miro-client-id", Within: "5L"},
		},
		ValidateExpr: `let r = http.post("https://api.miro.com/v1/oauth/token", {
    "Content-Type": "application/x-www-form-urlencoded",
    "Accept": "application/json"
  }, "grant_type=refresh_token" +
  "&client_id=" + strings.urlQueryEscape((components["miro-client-id"]?.secret ?? "")) +
  "&client_secret=" + strings.urlQueryEscape(finding["secret"]) +
  "&refresh_token=invalid"); r.status == 401
    && (r.json?.code ?? "") == "oauthError"
    && (r.json?.message ?? "") == "Invalid refresh token" ? {
    "result": "valid"
  } : r.status == 401 && (
    (r.json?.code ?? "") == "secretKeyNotFound" ||
    ((r.json?.code ?? "") == "oauthError" && (r.json?.message ?? "") == "Unauthorized grant type")
  ) ? {
    "result": "invalid",
    "reason": (r.json?.message ?? "Invalid client credentials")
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.5),
	}

	clientSecret := secrets.NewSecretWithEntropy(`[A-Za-z0-9]{32}`, 3.5)
	tps := utils.GenerateSampleSecrets("miro", clientSecret)
	tps = append(tps, `MIRO_CLIENT_SECRET=`+clientSecret)
	fps := []string{
		`CLIENT_SECRET=5VEWim0jDbaytgKXN7ReM7MkfpQ8Rm3d`,
		`MIRO_CLIENT_SECRET=5VEWim0jDbaytgKXN7ReM7MkfpQ8Rm3`,
	}
	return utils.Validate(r, tps, fps)
}
