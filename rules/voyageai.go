package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "voyageai-api-key",
	Confidence:  "medium",
	Description: "Detected a Voyage AI API key, which may expose embedding and retrieval model access to unauthorized parties.",
	Regex:       Assignment([]string{"voyage"}, `(?:pa|al)-[A-Za-z0-9_-]{43}`),
	Keywords:    []string{"voyage"},
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
	FilterExpr: MinEntropy(4.0),
	Tests: []config.RuleTest{
		Match("true positive 1", "VOYAGEAI_API_KEY=pa-WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH9", "pa-WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH9"),
		Match("true positive 2", "VOYAGEAI_API_KEY=al-WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH9", "al-WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH9"),
		NoMatch("false positive 1", "VOYAGEAI_API_KEY=pa-short"),
		NoMatch("false positive 2", "VOYAGEAI_API_KEY=qa-WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH9"),
		NoMatch("false positive 3", "VOYAGEAI_API_KEY=pa-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
	},
})
