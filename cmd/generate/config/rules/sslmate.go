package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func SSLMateAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "sslmate-api-key.1",
		Description: "SSLMate API key.",
		Regex: utils.GenerateSemiGenericRegex(
			[]string{`sslmate(?:[_. -]*(?:api))?[_. -]*(?:secret|key|token)`},
			`[A-Za-z0-9]{36}`,
			false,
		),
		Keywords: []string{"sslmate"},
		ValidateExpr: `let r = http.get("https://sslmate.com/api/v2/certs/example.com", {
    "Authorization": "Basic " + base64.encode(bytes(finding["secret"] + ":")),
    "Accept": "application/json"
  }); r.status == 200 && (r.body contains "\"cn\"")
    && (r.body contains "\"exists\"") ? {
    "result": "valid"
  } : r.status == 401 && (r.json?.reason ?? "") == "bad_credentials" ? {
    "result": "invalid",
    "reason": "Bad credentials"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.5),
	}

	// validate
	tps := []string{
		"SSLMATE_API_KEY=" + secrets.NewSecretWithEntropy(utils.AlphaNumeric("36"), 3.5),
	}
	fps := []string{
		`API_KEY=ABCDEFGHIJ1234567890ABCDEFGHIJ123456`,
		`SSLMATE_API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`,
	}
	return utils.Validate(r, tps, fps)
}
