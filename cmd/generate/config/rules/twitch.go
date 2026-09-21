package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

// https://dev.twitch.tv/docs/authentication/validate-tokens/
// https://dev.twitch.tv/docs/authentication/revoke-tokens/
const twitchRevokeExpr = `let lookup = http.get("https://id.twitch.tv/oauth2/validate", {
  "Authorization": "OAuth " + finding["secret"]
});
lookup.status != 200 ? revoke.unknown(lookup) : (
  let client_id = lookup.json?.client_id ?? "";
  type(client_id) != "string" || client_id == "" ? {
    "result": "unknown", "reason": "Twitch did not return a client ID"
  } : (
    let r = http.post("https://id.twitch.tv/oauth2/revoke", {
      "Content-Type": "application/x-www-form-urlencoded"
    }, "client_id=" + strings.urlQueryEscape(client_id) + "&token=" + strings.urlQueryEscape(finding["secret"]));
    r.status == 200 ? {"result": "revoked"} : revoke.unknown(r)
  )
)`

// https://dev.twitch.tv/docs/authentication/validate-tokens/
// https://dev.twitch.tv/docs/authentication/scopes/
const twitchValidateExpr = `let r = http.get("https://id.twitch.tv/oauth2/validate", {
  "Authorization": "OAuth " + finding["secret"],
  "Accept": "application/json"
});
r.status == 200 && type(r.json) == "map" && type(r.json?.client_id) == "string" && r.json.client_id != "" ? {
  "result": "valid",
  "analysis": {
    "user_id": string(r.json?.user_id ?? ""),
    "username": string(r.json?.login ?? ""),
    "client_id": string(r.json?.client_id ?? ""),
    "scopes": type(r.json?.scopes) == "array" ? filter(r.json.scopes, {type(#) == "string"}) : [],
    "expires_in": r.json?.expires_in
  }
} : r.status == 401 ? {"result": "invalid", "reason": "Unauthorized"} : validate.unknown(r)`

const twitchAnalyzeExpr = `let input = validation.analysis;
let scopes = input["scopes"] ?? [];
let capabilities = analysis.capabilities({
  "read": matchesAny(scopes, ["^(?:user|channel|moderator):read:[a-z_]+$"]) || any(scopes, {# in ["analytics:read:extensions", "analytics:read:games", "bits:read", "chat:read", "whispers:read", "user:manage:whispers"]}),
  "write": matchesAny(scopes, ["^(?:user|channel|moderator):manage:[a-z_]+$"]) || any(scopes, {# in ["user:edit", "user:edit:broadcast", "user:edit:follows", "user:write:chat", "chat:edit", "clips:edit", "whispers:edit", "channel:edit:commercial", "channel:moderate"]}),
  "read_secrets": "channel:read:stream_key" in scopes,
  "manage_users": any(scopes, {# in ["channel:manage:moderators", "channel:manage:vips"]})
});
{
  "identity": {"id": input["user_id"] ?? "", "username": input["username"] ?? ""},
  "metadata": {"client_id": input["client_id"] ?? "", "scopes": scopes, "expires_in": input["expires_in"] ?? nil},
  "capabilities": capabilities,
  "reason": len(capabilities) == 0 ? "Twitch returned no recognized permission grants" : ""
}`

func TwitchAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		ValidateExpr: twitchValidateExpr,
		AnalyzeExpr:  twitchAnalyzeExpr,
		ID:           "twitch-api-token",
		Confidence:   "medium",
		Description:  "Discovered a Twitch API token, which could compromise streaming services and account integrations.",
		Regex:        utils.GenerateSemiGenericRegex([]string{"twitch"}, utils.AlphaNumeric("30"), true),
		RevokeExpr:   twitchRevokeExpr,
		Keywords: []string{
			"twitch",
		},
		Filter: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("twitch", secrets.NewSecretWithEntropy(utils.AlphaNumeric("30"), 3.5))
	return utils.Validate(r, tps, nil)
}
