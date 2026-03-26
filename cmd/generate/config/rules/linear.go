package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func LinearAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "linear-api-key",
		Description: "Detected a Linear API Token, posing a risk to project management tools and sensitive task data.",
		Regex:       regexp.MustCompile(`lin_api_(?i)[a-z0-9]{40}`),
		Entropy:     2,
		Keywords:    []string{"lin_api_"},
		ValidateCEL: `cel.bind(r,
  http.post("https://api.linear.app/graphql", {
    "Authorization": secret,
    "Content-Type": "application/json"
  }, "{\"query\": \"query { viewer { id name email } }\"}"),
  r.status == 200 && r.body.contains("\"data\"") && r.body.contains("\"viewer\"") ? {
    "result": "valid",
    "email": r.json.?data.?viewer.?email.orValue(""),
    "name": r.json.?data.?viewer.?name.orValue("")
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("linear", "lin_api_"+secrets.NewSecretWithEntropy(utils.AlphaNumeric("40"), 2))
	return utils.Validate(r, tps, nil)
}

func LinearClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "linear-client-secret",
		Description: "Identified a Linear Client Secret, which may compromise secure integrations and sensitive project management data.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"linear"}, utils.Hex("32"), true),
		Entropy:     2,
		Keywords:    []string{"linear"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("linear", secrets.NewSecretWithEntropy(utils.Hex("32"), 2))
	return utils.Validate(r, tps, nil)
}
