package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
)

func CratesIOAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "crates-io-api-key",
		Description: "crates.io API key.",
		Regex:       utils.GenerateSemiGenericRegex([]string{`crates(?:[_.-]?io)?`}, `cio[A-Za-z0-9]{32}`, true),
		Keywords:    []string{"crates"},
		ValidateExpr: `let r = http.get("https://crates.io/api/v1/me", {
    "Authorization": finding["secret"]
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	}

	// validate
	tps := []string{
		`CRATES_IO_API_KEY=ciotgp8BGZBlX192iExSQPm0SrUlBunG8zd`,
	}
	fps := []string{
		`cio_short`,
	}
	return utils.Validate(r, tps, fps)
}
