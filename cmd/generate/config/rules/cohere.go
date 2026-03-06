package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func CohereAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "cohere-api-token",
		Description: "Identified a Cohere Token, posing a risk of unauthorized access to AI services and data manipulation.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"cohere", "CO_API_KEY"}, `[a-zA-Z0-9]{40}`, false),
		Entropy:     4,
		Keywords: []string{
			"cohere",
			"CO_API_KEY",
		},
		ValidateCEL: `cel.bind(r,
  http.get("https://api.cohere.com/v1/connectors", {
    "Authorization": "Bearer " + secret
  }),
  r.status == 200 && r.body.contains('"connectors"') && r.body.contains('"total_count"') ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("cohere", secrets.NewSecretWithEntropy(`[a-zA-Z0-9]{40}`, 4)),
		// https://github.com/cohere-ai/cohere-go/blob/abe8044073ed498ffbb206a602d03c2414b64512/client/client.go#L38C30-L38C40
		`export CO_API_KEY=` + secrets.NewSecretWithEntropy(`[a-zA-Z0-9]{40}`, 4),
	}
	fps := []string{
		`CO_API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`,
	}
	return utils.Validate(r, tps, fps)
}
