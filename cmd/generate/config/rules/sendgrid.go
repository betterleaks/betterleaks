package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

// https://www.twilio.com/docs/sendgrid/api-reference/api-key-permissions
// Scope inspection only: never send mail or create a key to test permissions.
const sendgridValidateExpr = `let r = http.get("https://api.sendgrid.com/v3/scopes", {
  "Authorization": "Bearer " + finding["secret"],
  "Accept": "application/json"
});
r.status == 200 && type(r.json) == "map" && type(r.json?.scopes) == "array" && all(r.json.scopes, {type(#) == "string"}) ? {
  "result": "valid",
  "analysis": {
    "scopes": r.json.scopes
  }
} : r.status == 401 ? {"result": "invalid", "reason": "Unauthorized"} : validate.unknown(r)`

const sendgridAnalyzeExpr = `let scopes = validation.analysis["scopes"] ?? [];
let capabilities = analysis.capabilities({
  "read": matchesAny(scopes, ["^(?:alerts|api_keys|asm|categories|contactdb|credentials|ips|mail|mail_settings|marketing|messages|partner_settings|stats|subusers|suppression|teammates|templates|tracking_settings|user|whitelabel)(?:[.][a-z0-9_]+)*[.]read$"]),
  "write": "mail.send" in scopes || matchesAny(scopes, ["^(?:alerts|api_keys|asm|categories|contactdb|credentials|ips|mail|mail_settings|marketing|partner_settings|subusers|suppression|teammates|templates|tracking_settings|user|whitelabel)(?:[.][a-z0-9_]+)*[.](?:create|update|delete)$"]),
  "create_credentials": "api_keys.create" in scopes || "credentials.create" in scopes,
  "manage_users": matchesAny(scopes, ["^(?:teammates|subusers)[.](?:create|update|delete)$"])
});
{
  "metadata": {"scopes": scopes},
  "capabilities": capabilities,
  "reason": len(capabilities) == 0 ? "SendGrid returned no recognized permission grants" : ""
}`

func SendGridAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		ValidateExpr: sendgridValidateExpr,
		AnalyzeExpr:  sendgridAnalyzeExpr,
		ID:           "sendgrid-api-token",
		Confidence:   "high",
		Description:  "Detected a SendGrid API token, posing a risk of unauthorized email service operations and data exposure.",
		Regex:        utils.GenerateUniqueTokenRegex(`SG\.(?i)[a-z0-9=_\-\.]{66}`, false),
		Keywords: []string{
			"SG.",
		},
		Filter: `entropy(finding["secret"]) <= 2.0`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("sengridAPIToken", "SG."+secrets.NewSecretWithEntropy(utils.AlphaNumericExtended("66"), 2))
	return utils.Validate(r, tps, nil)
}
