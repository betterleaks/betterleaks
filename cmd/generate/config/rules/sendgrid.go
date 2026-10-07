package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func SendGridAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "sendgrid-api-token",
		Confidence:  "high",
		Description: "Detected a SendGrid API token, posing a risk of unauthorized email service operations and data exposure.",
		Regex:       utils.GenerateUniqueTokenRegex(`SG\.(?i)[a-z0-9=_\-\.]{66}`, false),
		Keywords: []string{
			"SG.",
		},
		Filter: `entropy(finding["secret"]) <= 2.0`,
		ValidateExpr: `let r = http.get("https://api.sendgrid.com/v3/scopes", {
  "Authorization": "Bearer " + finding["secret"],
  "Accept": "application/json"
});
r.status == 200 && type(r.json) == "map" && type(r.json?.scopes) == "array" && all(r.json.scopes, {type(#) == "string"}) ? {
  "result": "valid"
} : r.status == 401 ? {"result": "invalid", "reason": "Unauthorized"} : validate.unknown(r)
`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("sengridAPIToken", "SG."+secrets.NewSecretWithEntropy(utils.AlphaNumericExtended("66"), 2))
	return utils.Validate(r, tps, nil)
}
