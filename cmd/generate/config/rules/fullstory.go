package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func FullStoryAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "fullstory-api-key",
		Description: "FullStory API key.",
		Regex: utils.GenerateSemiGenericRegex(
			[]string{`(?:fullstory|fs_api|fullstory_api)`},
			`(?:na1|eu1)\.[A-Za-z0-9]{20,}`,
			true,
		),
		Keywords: []string{"fullstory", "fs_api"},
		ValidateExpr: `let r = http.get("https://api.fullstory.com/me", {
    "Authorization": "Basic " + base64.encode(bytes(finding["secret"] + ":")),
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.3),
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("fullstory", "na1."+secrets.NewSecretWithEntropy(utils.AlphaNumeric("32"), 3.3)),
	}
	fps := []string{
		`FULLSTORY_API_KEY=na1.short`,
	}
	return utils.Validate(r, tps, fps)
}
