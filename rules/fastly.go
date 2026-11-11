package rules

import "github.com/betterleaks/betterleaks/v2/config"

const fastlyValidateExpr = `let r = http.get("https://api.fastly.com/tokens/self", {
    "Accept": "application/json",
    "Fastly-Key": finding["secret"]
  }); r.status == 200 && (r.json?.id ?? "") != "" ? {
    "result": "valid",
    "analysis": {
      "token_id": string(r.json?.id ?? ""),
      "token_name": (r.json?.name ?? ""),
      "user_id": string(r.json?.user_id ?? ""),
      "scopes": strings.splitTrim((r.json?.scope ?? ""), " "),
      "services": (r.json?.services ?? []),
      "expires_at": (r.json?.expires_at ?? "")
    }
  } : r.status == 401 ? {
    "result": "revoked",
    "reason": "Token expired"
  } : r.status == 403 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`

// Fastly currently documents four scopes. Match them exactly so a future
// scope remains unknown until its security meaning is understood.
// https://www.fastly.com/documentation/reference/api/auth-tokens/user/#scopes
const fastlyAnalyzeExpr = `let input = validation.analysis;
let scopes = input["scopes"] ?? [];
let services = input["services"] ?? [];
let known_scopes = ["global", "global:read", "purge_all", "purge_select"];
{
  "reason": len(scopes) == 0 ? "Fastly did not return token scope metadata" :
    !intersects(scopes, known_scopes) ? "Fastly returned no recognized token scopes" : "",
  "identity": {
    "id": input["user_id"] ?? ""
  },
  "metadata": {
    "token_id": input["token_id"] ?? "",
    "token_name": input["token_name"] ?? "",
    "scopes": scopes,
    "service_ids": services,
    "all_services": len(services) == 0,
    "expires_at": input["expires_at"] ?? ""
  },
  "capabilities": analysis.capabilities({
    "read": intersects(scopes, ["global", "global:read"]),
    "write": intersects(scopes, ["global", "purge_all", "purge_select"])
  })
}`

var _ = Add(config.Rule{
	Description:  "Uncovered a Fastly API token, which may compromise CDN and edge cloud services, leading to content delivery and security issues.",
	ID:           "fastly-api-token",
	Confidence:   "high",
	Regex:        Assignment([]string{"fastly"}, `(?i)`+AlphaNumericExtendedShort("32")),
	Keywords:     []string{"fastly"},
	ValidateExpr: fastlyValidateExpr,
	AnalyzeExpr:  fastlyAnalyzeExpr,
	FilterExpr:   `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("fastly assignment", `fastlyToken = "4v8l67z---wfu0y1vd_3l1cmfzxoud8e"`, "4v8l67z---wfu0y1vd_3l1cmfzxoud8e"),
		Match("true positive 1", "Fastly token: fgsb3ef237afd6c1b9d91f81cdba64f3", "fgsb3ef237afd6c1b9d91f81cdba64f3"),
	},
})
