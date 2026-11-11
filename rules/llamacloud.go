package rules

import "github.com/betterleaks/betterleaks/v2/config"

// LlamaCloud keys can be region-specific. Only a successful response from
// the global API proves validity; a non-success remains unknown.
var _ = Add(config.Rule{
	ID:          "llama-cloud-api-key.1",
	Confidence:  "high",
	Description: "LlamaCloud API key, which may allow access to managed parsing, ingestion, and retrieval projects.",
	Regex:       Token(`llx-[A-Za-z0-9]{44,52}`),
	Keywords:    []string{"llx-"},
	ValidateExpr: `let r = http.get("https://api.cloud.llamaindex.ai/api/v1/projects", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : validate.unknown(r)`,
	FilterExpr: MinEntropy(3.5),
	Tests: []config.RuleTest{
		Match("true positive 1", "LLAMA_CLOUD_API_KEY=llx-RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klKiz9pyK", "llx-RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klKiz9pyK"),
		Match("true positive 2", `llama_api_key: "llx-RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klKiz9pyK"`, "llx-RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klKiz9pyK"),
		NoMatch("false positive 1", "LLAMA_CLOUD_API_KEY=llx-short"),
		NoMatch("false positive 2", "LLAMA_CLOUD_API_KEY=llx-000000000000000000000000000000000000000000000000"),
	},
})
