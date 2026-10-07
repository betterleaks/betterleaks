package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

// RubyGemsAPIToken validates by listing the owner's gems, a read-only call that needs no OTP.
// https://guides.rubygems.org/rubygems-org-api/
func RubyGemsAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		ID:          "rubygems-api-token",
		Confidence:  "high",
		Description: "Identified a Rubygem API token, potentially compromising Ruby library distribution and package management.",
		Regex:       utils.GenerateUniqueTokenRegex(`rubygems_[a-f0-9]{48}`, false),
		Keywords: []string{
			"rubygems_",
		},
		// Keys without the index scope get 403. Soft-deleted keys get 403 "invalid API key".
		ValidateExpr: `let r = http.get("https://rubygems.org/api/v1/gems.json", {
    "Authorization": finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status == 403 && (r.body contains "invalid API key") ? {
    "result": "revoked",
    "reason": "API key was deleted"
  } : r.status == 403 ? {
    "result": "valid",
    "reason": "API key lacks the index scope"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
		FilterExpr: `entropy(finding["secret"]) <= 2.0`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("rubygemsAPIToken", "rubygems_"+secrets.NewSecretWithEntropy(utils.Hex("48"), 2))
	return utils.Validate(r, tps, nil)
}
