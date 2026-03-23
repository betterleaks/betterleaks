package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func HarnessApiKey() *config.Rule {
	// Define rule for Harness Personal Access Token (PAT) and Service Account Token (SAT)
	r := config.Rule{
		Description: "Identified a Harness Access Token (PAT or SAT), risking unauthorized access to a Harness account.",
		RuleID:      "harness-api-key",
		Regex:       regexp.MustCompile(`(?:pat|sat)\.[a-zA-Z0-9_-]{22}\.[0-9a-f]{24}\.[a-zA-Z0-9]{20}`),
		Keywords:    []string{"pat.", "sat."},
		Entropy:     3.4,
		ValidateCEL: `cel.bind(r,
  http.get("https://app.harness.io/v1/orgs?limit=1&page=1", {
    "Accept": "application/json",
    "x-api-key": secret
  }),
  r.status in [200, 403] ? {
    "result": "valid"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	}

	// Generate a sample secret for validation
	tps := utils.GenerateSampleSecrets("harness", "pat."+secrets.NewSecret(`[a-zA-Z0-9_-]{22}`)+"."+secrets.NewSecretWithEntropy(`[0-9a-f]{24}`, 3.4)+"."+secrets.NewSecretWithEntropy(utils.AlphaNumeric("20"), 3.4))
	tps = append(tps, utils.GenerateSampleSecrets("harness", "sat."+secrets.NewSecret(`[a-zA-Z0-9_-]{22}`)+"."+secrets.NewSecretWithEntropy(`[0-9a-f]{24}`, 3.4)+"."+secrets.NewSecretWithEntropy(utils.AlphaNumeric("20"), 3.4))...)
	tps = append(tps,
		`HARNESS_TOKEN="pat.AbCdEfGhIjKlMnOpQrStUv.0123abcd4567ef890123abcd.ZyXwVuTsRqPoNmLkJiHg"`,
	)

	// validate the rule
	return utils.Validate(r, tps, nil)
}
