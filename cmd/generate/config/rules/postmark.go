package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func PostmarkAPIToken() *config.Rule {
	// Server and account tokens share the UUID shape. Try the read-only server
	// endpoint first, then the account endpoint, and reject the token only when
	// both authentication schemes return Postmark's documented 401 response.
	r := config.Rule{
		RuleID:      "postmark-api-token.1",
		Confidence:  "high",
		Description: "Postmark server or account API token, which may allow access to email delivery and account configuration.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"postmark"}, utils.Hex8_4_4_4_12(), true),
		Keywords:    []string{"postmark"},
		ValidateExpr: `let server = http.get("https://api.postmarkapp.com/server", {
    "X-Postmark-Server-Token": finding["secret"],
    "Accept": "application/json"
  }); server.status == 200 && (server.body contains "\"ID\"") ? {
    "result": "valid",
    "type": "server"
  } : (let account = http.get("https://api.postmarkapp.com/domains?count=1&offset=0", {
    "X-Postmark-Account-Token": finding["secret"],
    "Accept": "application/json"
  }); account.status == 200 ? {
    "result": "valid",
    "type": "account"
  } : server.status == 401 && account.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(account))`,
		Filter: utils.MinEntropy(3.0),
	}

	token := secrets.NewSecretWithEntropy(utils.Hex8_4_4_4_12(), 3.0)
	tps := []string{
		`POSTMARK_SERVER_TOKEN=` + token,
		`postmark: "` + token + `"`,
		`postmark_account_api_token=` + token,
	}
	fps := []string{
		`SERVER_TOKEN=` + token,
		`POSTMARK_SERVER_TOKEN=00000000-0000-0000-0000-000000000000`,
		`POSTMARK_SERVER_TOKEN=short`,
	}
	return utils.Validate(r, tps, fps)
}
