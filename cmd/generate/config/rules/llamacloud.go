package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func LlamaCloudAPIKey() *config.Rule {
	// LlamaCloud keys can be region-specific. Only a successful response from
	// the global API proves validity; a non-success remains unknown.
	r := config.Rule{
		RuleID:      "llama-cloud-api-key.1",
		Confidence:  "high",
		Description: "LlamaCloud API key, which may allow access to managed parsing, ingestion, and retrieval projects.",
		Regex:       utils.GenerateUniqueTokenRegex(`llx-[A-Za-z0-9]{44,52}`, false),
		Keywords:    []string{"llx-"},
		ValidateExpr: `let r = http.get("https://api.cloud.llamaindex.ai/api/v1/projects", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.5),
	}

	key := "llx-" + secrets.NewSecretWithEntropy(`[A-Za-z0-9]{48}`, 3.5)
	tps := []string{
		`LLAMA_CLOUD_API_KEY=` + key,
		`llama_api_key: "` + key + `"`,
	}
	fps := []string{
		`LLAMA_CLOUD_API_KEY=llx-short`,
		`LLAMA_CLOUD_API_KEY=llx-000000000000000000000000000000000000000000000000`,
	}
	return utils.Validate(r, tps, fps)
}
