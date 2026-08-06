package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func MailerSendAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "mailersend-api-token",
		Description: "MailerSend API token.",
		Regex:       utils.GenerateUniqueTokenRegex(`mlsn\.[A-Za-z0-9]{30,100}`, false),
		Keywords:    []string{"mlsn."},
		ValidateExpr: `let r = http.get("https://api.mailersend.com/v1/api-quota", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.5),
	}

	// validate
	tps := []string{
		"MAILERSEND_API_TOKEN=mlsn." + secrets.NewSecretWithEntropy(utils.AlphaNumeric("48"), 3.5),
	}
	fps := []string{
		`MAILERSEND_API_TOKEN=mlsn.short`,
		`MAILERSEND_API_TOKEN=mlsn.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`,
	}
	return utils.Validate(r, tps, fps)
}
