package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func VoyageAIAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "voyageai-api-key",
		Confidence:  "medium",
		Description: "Detected a Voyage AI API key, which may expose embedding and retrieval model access to unauthorized parties.",
		Regex:       utils.GenerateUniqueTokenRegex(`(?:pa|al)-[A-Za-z0-9_-]{43}`, false),
		Keywords:    []string{"pa-", "al-"},
		ValidateExpr: `let r = http.post("https://api.voyageai.com/v1/embeddings", {
    "Authorization": "Bearer " + finding["secret"],
    "Content-Type": "application/json"
  }, "{\"input\":\"hi\",\"model\":\"nonexistent-model-xyz-12345\"}");
  let invalidResponse = (r.body contains "Provided API key is invalid") ||
    (r.body contains "cannot access this endpoint");
  r.status == 401 || invalidResponse ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : r.status in [200, 400, 403] ? {
    "result": "valid"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(4.0),
	}

	paKey := "pa-" + secrets.NewSecretWithEntropy(`[A-Za-z0-9_-]{43}`, 4.0)
	alKey := "al-" + secrets.NewSecretWithEntropy(`[A-Za-z0-9_-]{43}`, 4.0)
	tps := []string{
		`VOYAGEAI_API_KEY=` + paKey,
		`VOYAGEAI_API_KEY=` + alKey,
	}
	fps := []string{
		`VOYAGEAI_API_KEY=pa-short`,
		`VOYAGEAI_API_KEY=qa-` + secrets.NewSecret(`[A-Za-z0-9_-]{43}`),
		`VOYAGEAI_API_KEY=pa-` + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
	return utils.Validate(r, tps, fps)
}
