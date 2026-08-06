package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
)

func DatabentoAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "databento-api-key",
		Description: "Databento API key.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"databento"}, `db-[A-Za-z0-9]{29}`, true),
		Keywords:    []string{"databento"},
		ValidateExpr: `let r = http.get("https://hist.databento.com/v0/metadata.list_datasets", {
    "Authorization": "Basic " + base64.encode(bytes(finding["secret"] + ":"))
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	}

	// validate
	tps := []string{
		`DATABENTO_API_KEY=db-abc123def456ghi789jkl012mno34`,
	}
	fps := []string{
		`db-short`,
	}
	return utils.Validate(r, tps, fps)
}
