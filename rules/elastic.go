package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "elastic-cloud-api-key",
	Confidence:  "high",
	Description: "Identified an Elastic Cloud Serverless API key, which may expose Elasticsearch and Kibana resources to unauthorized access.",
	Regex:       Token(`essu_[A-Za-z0-9_\-]{60,200}={0,2}`),
	Keywords:    []string{"essu_"},
	FilterExpr:  MinEntropy(3.5),
	ValidateExpr: `let r = http.get("https://api.elastic-cloud.com/api/v1/deployments", {
    "Authorization": "ApiKey " + finding["secret"]
  }); r.status == 200 && (r.body contains '"deployments"') ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	Tests: []config.RuleTest{
		Match("elastic assignment", `elasticToken = "essu_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG7ubf2TxReZd1UXAceqba86wo"`, "essu_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG7ubf2TxReZd1UXAceqba86wo"),
		NoMatch("Too short", "elastic_token = essu_abc123"),
		NoMatch("Wrong prefix", "elastic_token = ess_abc123def456ghi789jkl012mno345pqr678stu901vwx234yz1234567890"),
	},
})
