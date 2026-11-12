package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "disqus-api-key",
	Confidence:  "high",
	Description: "Detected a Disqus API key, which may expose Disqus thread and account data.",
	Regex:       rulebuilder.Assignment([]string{"disqus"}, `(?i)`+rulebuilder.AlphaNumeric("64")),
	Keywords:    []string{"disqus"},
	ValidateExpr: `let r = http.get("https://disqus.com/api/3.0/threads/list.json?limit=1&api_secret=" + finding["secret"], {
    "Accept": "application/json"
  }); r.status == 200 && (r.body contains "\"code\":0") && (r.body contains "\"response\"") ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "disqus_secret_key = jK5HbxY2QrPn7vMNL8tADcF3mWg4kXqR9sBdZyE1hVuT6fGwJpC0nI9vUxY2aM3K", "jK5HbxY2QrPn7vMNL8tADcF3mWg4kXqR9sBdZyE1hVuT6fGwJpC0nI9vUxY2aM3K"),
		rulebuilder.Match("true positive 2", "DISQUS_PRIVATE_TOKEN = Nh7vRf3mKp9wXc5tJq2YbL8sAg4dB6TzWeUx1nGQjCkPyDHVME0aI1FSx2Z5vY3n", "Nh7vRf3mKp9wXc5tJq2YbL8sAg4dB6TzWeUx1nGQjCkPyDHVME0aI1FSx2Z5vY3n"),
	},
})
