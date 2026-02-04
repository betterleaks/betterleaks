package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func CohereAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "cohere-api-token",
		Description: "Identified a Cohere Token, posing a risk of unauthorized access to AI services and data manipulation.",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"cohere", "CO_API_KEY"}, `[a-zA-Z0-9]{40}`, false),
		Entropy:     4,
		Keywords: []string{
			"cohere",
			"CO_API_KEY",
		},
	}

	// validate
	tps := []string{
		utils2.GenerateSampleSecret("cohere", secrets.NewSecret(`[a-zA-Z0-9]{40}`)),
		// https://github.com/cohere-ai/cohere-go/blob/abe8044073ed498ffbb206a602d03c2414b64512/client/client.go#L38C30-L38C40
		`export CO_API_KEY=` + secrets.NewSecret(`[a-zA-Z0-9]{40}`),
	}
	fps := []string{
		`CO_API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`,
	}
	return utils2.Validate(r, tps, fps)
}
