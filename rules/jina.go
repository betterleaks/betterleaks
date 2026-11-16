package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "jina-ai-api-key",
	Confidence:  "high",
	Description: "Detected a Jina AI API key, which may allow unauthorized access to embeddings, rerankers, and other Jina AI services.",
	Regex:       rulebuilder.Token(`jina_[A-Za-z0-9_\-]{60}`),
	Keywords:    []string{"jina_"},
	ValidateExpr: `let r = http.get("https://api.jina.ai/v1/batches?" + "limit=1", {"Authorization": "Bearer " + finding["secret"], "User-Agent": "Go-http-client/1.1"});
(r.status in [200]) ? {"result": "valid"} :
(r.status in [401]) ? {"result": "invalid"} :
validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) <= 3.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("shape 1", `token = "jina_LUalQaJFiBfC15V5px_YQZ4QHpw4Bq75PK4Dj4z0TIIUPdiig9ED9qOmnBIA"`, `jina_LUalQaJFiBfC15V5px_YQZ4QHpw4Bq75PK4Dj4z0TIIUPdiig9ED9qOmnBIA`),
		rulebuilder.NoMatch("near miss 1", `token = "jina_Ds6irxBB7dBADK-UA5B3ePi3MMFVlMppb87AO6-kQqqItMh6MQv1bDmZ3uC"`),
		rulebuilder.NoMatch("near miss 2", `token = "jina_5Cv5ca7xkdf4YYvOC1xip3B8yEWRNwc3smfbqHh1jKXB_O6l4K6m_uNoMzGQe"`),
	},
})
