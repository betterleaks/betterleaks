package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

// https://replicate.com/docs/reference/http#account.get
const replicateValidateExpr = `let r = http.get("https://api.replicate.com/v1/account", {
  "Authorization": "Bearer " + finding["secret"],
  "Accept": "application/json"
});
r.status == 200 && type(r.json) == "map" && (r.json?.username ?? "") != "" && (r.json?.type ?? "") in ["user", "organization"] ? {
  "result": "valid",
  "analysis": {
    "identity": {
      "username": r.json.type == "user" ? string(r.json.username) : "",
      "name": r.json.type == "user" ? string(r.json?.name ?? "") : "",
      "account": r.json.type == "organization" ? {"id": string(r.json.username), "name": string(r.json?.name ?? "")} : nil
    },
    "metadata": {
      "account_type": r.json.type
    }
  }
} : r.status == 401 ? {
  "result": "invalid", "reason": "Unauthorized"
} : validate.unknown(r)`

const replicateAnalyzeExpr = identityOnlyAnalyzeExpr

func Replicate() *config.Rule {
	r := config.Rule{
		ID:           "replicate-api-token",
		Confidence:   "high",
		Description:  "Detected a Replicate API Token, which may expose AI model hosting and inference services to unauthorized access.",
		Regex:        utils.GenerateUniqueTokenRegex(`r8_[A-Za-z0-9]{37}`, true),
		Keywords:     []string{"r8_"},
		ValidateExpr: replicateValidateExpr,
		AnalyzeExpr:  replicateAnalyzeExpr,
		FilterExpr:   `entropy(finding["secret"]) <= 3.0`,
	}

	tps := utils.GenerateSampleSecrets("replicate", "r8_"+secrets.NewSecretWithEntropy(`[A-Za-z0-9]{37}`, 3.0))
	fps := []string{
		// Too short
		`r8_WesXNvqsCpq7r1gpQABpB3NJvdR`,
		// Wrong prefix
		`r9_WesXNvqsCpq7r1gpQABpB3NJvdR21nb2s7HVy`,
	}
	return utils.Validate(r, tps, fps)
}
