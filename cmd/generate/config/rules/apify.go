package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/config"
)

// https://docs.apify.com/api/v2/users-me-get
const apifyValidateExpr = `let r = http.get("https://api.apify.com/v2/users/me", {
  "Authorization": "Bearer " + finding["secret"],
  "Accept": "application/json"
});
r.status == 200 && type(r.json) == "map" && type(r.json?.data) == "map" && (r.json?.data?.id ?? "") != "" ? {
  "result": "valid",
  "analysis": {
    "identity": {
      "id": string(r.json?.data?.id ?? ""),
      "username": string(r.json?.data?.username ?? ""),
      "email": string(r.json?.data?.email ?? "")
    },
    "metadata": {}
  }
} : r.status == 401 ? {
  "result": "invalid", "reason": "Unauthorized"
} : validate.unknown(r)`

const apifyAnalyzeExpr = identityOnlyAnalyzeExpr

func ApifyAPIToken() *config.Rule {
	r := config.Rule{
		ID:           "apify-api-token",
		Confidence:   "high",
		Description:  "Detected an Apify API token, which may expose actors, tasks, and stored data.",
		Regex:        `\b(apify_api_[A-Za-z0-9]{34,38})\b`,
		Keywords:     []string{"apify_api_"},
		ValidateExpr: apifyValidateExpr,
		AnalyzeExpr:  apifyAnalyzeExpr,
		FilterExpr:   utils.MinEntropy(3.5),
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
