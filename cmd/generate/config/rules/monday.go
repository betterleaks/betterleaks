package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

func MondayAPIToken() *config.Rule {
	r := config.Rule{
		RuleID:      "monday-api-token.1",
		Confidence:  "high",
		Specificity: 110,
		Description: "monday.com API token, which may grant the same workspace access as its associated user or application.",
		Regex: utils.GenerateSemiGenericRegex(
			[]string{"monday"},
			`eyJ[A-Za-z0-9_-]{10,200}\.eyJ[A-Za-z0-9_-]{50,1000}\.[A-Za-z0-9_-]{20,500}`,
			false,
		),
		Keywords: []string{"monday"},
		ValidateExpr: `let r = http.post("https://api.monday.com/v2", {
    "Authorization": finding["secret"],
    "Content-Type": "application/json",
    "Accept": "application/json"
  }, "{\"query\":\"query { me { id name } }\"}"); r.status == 200
    && (r.body contains "\"data\"") && (r.body contains "\"me\"")
    && (r.body contains "\"id\"") ? {
    "result": "valid"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.5),
	}

	token := "eyJ" + secrets.NewSecretWithEntropy(`[A-Za-z0-9_-]{40}`, 3.5) +
		".eyJ" + secrets.NewSecretWithEntropy(`[A-Za-z0-9_-]{120}`, 3.5) +
		"." + secrets.NewSecretWithEntropy(`[A-Za-z0-9_-]{43}`, 3.5)
	tps := []string{
		`MONDAY_API_TOKEN=` + token,
		`monday access token: "` + token + `"`,
	}
	fps := []string{
		`API_TOKEN=` + token,
		`MONDAY_API_TOKEN=eyJshort.eyJshort.short`,
	}
	return utils.Validate(r, tps, fps)
}
