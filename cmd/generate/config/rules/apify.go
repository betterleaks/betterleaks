package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func ApifyAPIToken() *config.Rule {
	r := config.Rule{
		RuleID:      "apify-api-token",
		Confidence:  "high",
		Description: "Detected an Apify API token, which may expose actors, tasks, and stored data.",
		Regex:       regexp.MustCompile(`\b(apify_api_[A-Za-z0-9]{34,38})\b`),
		Keywords:    []string{"apify_api_"},
		ValidateExpr: `let r = http.get("https://api.apify.com/v2/users/me", {
  "Authorization": "Bearer " + finding["secret"],
  "Accept": "application/json"
});
r.status == 200 && type(r.json) == "map" && type(r.json?.data) == "map" && (r.json?.data?.id ?? "") != "" ? {
  "result": "valid"
} : r.status == 401 ? {
  "result": "invalid", "reason": "Unauthorized"
} : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.5),
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
