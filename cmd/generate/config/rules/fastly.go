package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

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
  "reason": size(scopes) == 0 ? "Fastly did not return token scope metadata" :
    !filter.intersects(scopes, known_scopes) ? "Fastly returned no recognized token scopes" : "",
  "identity": {
    "id": input["user_id"] ?? ""
  },
  "metadata": {
    "token_id": input["token_id"] ?? "",
    "token_name": input["token_name"] ?? "",
    "scopes": scopes,
    "service_ids": services,
    "all_services": size(services) == 0,
    "expires_at": input["expires_at"] ?? ""
  },
  "capabilities": analysis.capabilities({
    "read": filter.intersects(scopes, ["global", "global:read"]),
    "write": filter.intersects(scopes, ["global", "purge_all", "purge_select"])
  })
}`

func FastlyAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description:  "Uncovered a Fastly API token, which may compromise CDN and edge cloud services, leading to content delivery and security issues.",
		RuleID:       "fastly-api-token",
		Confidence:   "high",
		Regex:        utils.GenerateSemiGenericRegex([]string{"fastly"}, utils.AlphaNumericExtendedShort("32"), true),
		Keywords:     []string{"fastly"},
		ValidateExpr: fastlyValidateExpr,
		AnalyzeExpr:  fastlyAnalyzeExpr,
		Filter:       `filter.entropy(finding["secret"]) < 3.5 || filter.tokenRatio(finding["secret"]) >= 2.5`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("fastly", secrets.NewSecretWithEntropy(utils.AlphaNumericExtendedShort("32"), 3.5))
	tps = append(tps, `Fastly token: fgsb3ef237afd6c1b9d91f81cdba64f3`)
	return utils.Validate(r, tps, nil)
}
