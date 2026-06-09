package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func BraveSearchAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "brave-search-api-key",
		Description: "Detected a Brave Search API key, which may allow unauthorized use of Brave Search API quota.",
		Regex:       regexp.MustCompile(`\b(BSA[A-Za-z0-9_-]{24,40})\b`),
		Keywords:    []string{"BSA"},
		ValidateCEL: `cel.bind(r,
  http.get("https://api.search.brave.com/res/v1/web/search?q=betterleaks&count=1", {
    "Accept": "application/json",
    "X-Subscription-Token": finding["secret"]
  }),
  r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)
)`,
		Filter: `filter.entropy(finding["secret"]) < 3.2`,
	}

	tps := []string{
		`BRAVE_SEARCH_API_KEY="BSAp7_Mi4q7zWv9NeL2asR0kF6hTbQx"`,
		`headers = {"X-Subscription-Token": "BSAk4_Vm8nDp3Qw7Ls0raF2jHx6ZuCt"}`,
	}
	fps := []string{
		`BRAVE_SEARCH_API_KEY="BSAshort"`,
		`BRAVE_SEARCH_API_KEY="BSAp7_Mi4q7zWv9NeL2asR0k"`,
	}
	return utils.Validate(r, tps, fps)
}
