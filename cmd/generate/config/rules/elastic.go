package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func ElasticCloudAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "elastic-cloud-api-key",
		Description: "Identified an Elastic Cloud Serverless API key, which may expose Elasticsearch and Kibana resources to unauthorized access.",
		Regex:       utils.GenerateUniqueTokenRegex(`essu_[A-Za-z0-9_\-]{60,200}={0,2}`, false),
		Keywords:    []string{"essu_"},
		Entropy:     3.5,
		ValidateCEL: `cel.bind(r,
  http.get("https://api.elastic-cloud.com/api/v1/deployments", {
    "Authorization": "ApiKey " + finding["secret"]
  }),
  r.status == 200 && r.body.contains('"deployments"') ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	}

	tps := utils.GenerateSampleSecrets("elastic", "essu_"+secrets.NewSecretWithEntropy(`[A-Za-z0-9_\-]{80}`, 3.5))
	fps := []string{
		// Too short
		`elastic_token = essu_abc123`,
		// Wrong prefix
		`elastic_token = ess_abc123def456ghi789jkl012mno345pqr678stu901vwx234yz1234567890`,
	}
	return utils.Validate(r, tps, fps)
}
