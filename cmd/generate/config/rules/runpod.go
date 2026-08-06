package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func RunPodAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "runpod-api-key.1",
		Description: "RunPod API key.",
		Regex:       utils.GenerateUniqueTokenRegex(`rpa_[A-Z0-9]{40}[A-Za-z0-9]{6}`, false),
		Keywords:    []string{"rpa_"},
		ValidateExpr: `let r = http.post("https://api.runpod.io/graphql", {
    "Authorization": "Bearer " + finding["secret"],
    "Content-Type": "application/json",
    "Accept": "application/json"
  }, "{\"query\":\"{ myself { id } }\"}"); r.status == 200
    && (r.json?.data?.myself?.id ?? "") != "" ? {
    "result": "valid"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.5),
	}

	// validate
	tps := []string{
		"RUNPOD_API_KEY=rpa_" + secrets.NewSecretWithEntropy(`[A-Z0-9]{40}`, 3.5) + secrets.NewSecret(`[A-Za-z0-9]{6}`),
	}
	fps := []string{
		`RUNPOD_API_KEY=rpa_short`,
		`REDIRECT_PIZZA_TOKEN=rpa_Qj7mN4vK8sL2xP6zT9aBcD3eF5gH1j`,
	}
	return utils.Validate(r, tps, fps)
}
