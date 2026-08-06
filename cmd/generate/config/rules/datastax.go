package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func DataStaxAstraApplicationToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "datastax-astra-application-token",
		Description: "DataStax Astra application token.",
		Regex:       regexp.MustCompile(`\b(AstraCS:[A-Za-z0-9]{20,})`),
		Keywords:    []string{"AstraCS:"},
		ValidateExpr: `let r = http.get("https://api.astra.datastax.com/v2/tokens", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(4.0),
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("datastax", "AstraCS:"+secrets.NewSecretWithEntropy(utils.AlphaNumeric("40"), 4.0)),
	}
	fps := []string{
		`ASTRA_DB_APPLICATION_TOKEN=AstraCS:short`,
	}
	return utils.Validate(r, tps, fps)
}
