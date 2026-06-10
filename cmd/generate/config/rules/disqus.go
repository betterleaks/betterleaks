package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
)

func DisqusAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "disqus-api-key",
		Description: "Detected a Disqus API key, which may expose Disqus thread and account data.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"disqus"}, utils.AlphaNumeric("64"), true),
		Keywords:    []string{"disqus"},
		ValidateCEL: `cel.bind(r,
  http.get("https://disqus.com/api/3.0/threads/list.json?limit=1&api_secret=" + finding["secret"], {
    "Accept": "application/json"
  }),
  r.status == 200 && r.body.contains("\"code\":0") && r.body.contains("\"response\"") ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)
)`,
		Filter: utils.MinEntropy(3.5),
	}

	tps := []string{
		`disqus_secret_key = jK5HbxY2QrPn7vMNL8tADcF3mWg4kXqR9sBdZyE1hVuT6fGwJpC0nI9vUxY2aM3K`,
		`DISQUS_PRIVATE_TOKEN = Nh7vRf3mKp9wXc5tJq2YbL8sAg4dB6TzWeUx1nGQjCkPyDHVME0aI1FSx2Z5vY3n`,
	}
	return utils.Validate(r, tps, nil)
}
