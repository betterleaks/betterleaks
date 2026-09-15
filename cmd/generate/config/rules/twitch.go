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

func TwitchAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		ID:          "twitch-api-token",
		Confidence:  "medium",
		Description: "Discovered a Twitch API token, which could compromise streaming services and account integrations.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"twitch"}, utils.AlphaNumeric("30"), true),
		RevokeExpr:  twitchRevokeExpr,
		Keywords: []string{
			"twitch",
		},
		Filter: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("twitch", secrets.NewSecretWithEntropy(utils.AlphaNumeric("30"), 3.5))
	return utils.Validate(r, tps, nil)
}
