package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func ApifyAPIToken() *config.Rule {
	r := config.Rule{
		RuleID:       "apify-api-token",
		Description:  "Detected an Apify API token, which may expose actors, tasks, and stored data.",
		Regex:        regexp.MustCompile(`\b(apify_api_[A-Za-z0-9]{34,38})\b`),
		Keywords:     []string{"apify_api_"},
		ValidateExpr: utils.BearerGetValidationExpr("https://api.apify.com/v2/users/me", `(r.body contains "\"data\"") && (r.body contains "\"username\"")`),
		Filter:       utils.MinEntropy(3.5),
	}

	return utils.Validate(r,
		[]string{
			`APIFY_TOKEN=apify_api_NcjXcxEz2XL1irjppyWSHvjghalQOd1LXOHv`,
			`"token": "apify_api_9uyewBxQUF1EXWdKVc4lNaTSM461Ls4oQouz"`,
			`?token=apify_api_NcjXcxEz2XL1irjppyWSHvjghalQOd1LXOHv&other=value`,
		},
		[]string{
			`APIFY_TOKEN=apify_api_tooShort`,
			`APIFY_TOKEN=APIFY_API_NcjXcxEz2XL1irjppyWSHvjghalQOd1LXOHv`,
			`APIFY_TOKEN=apify_api_NcjXcxEz2XL1irjppyWSHvjghalQOd1LXOHv_extra`,
			`?token=apify_api_NcjXcxEz2XL1irjppyWSHvjghalQOd1LXOHv_extra`,
		},
	)
}
