package rules

import "github.com/betterleaks/betterleaks/v2/config"

const pineconeValidateExpr = `let r = http.get("https://api.pinecone.io/indexes", {
    "Api-Key": finding["secret"],
    "X-Pinecone-Api-Version": "2025-10",
    "Accept": "application/json"
  }); r.status == 200 && (r.body contains "\"indexes\"") ? {
    "result": "valid"
  } : r.status == 403 ? {
    "result": "valid",
    "reason": "Authenticated but control-plane access is restricted"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`

var _ = Add(config.Rule{
	ID:          "pinecone-api-key.1",
	Confidence:  "medium",
	Description: "Pinecone API key version 1 (UUID format).",
	Regex: Assignment(
		[]string{`pinecone(?:[_. -]*(?:api))?[_. -]*(?:secret|key|token)`},
		`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`,
	),
	Keywords:     []string{"pinecone"},
	ValidateExpr: pineconeValidateExpr,
	FilterExpr:   MinEntropy(3.0),
	Tests: []config.RuleTest{
		Match("true positive 1", "PINECONE_API_KEY=62b0dbfe-3489-4b79-b850-34d911527c88", "62b0dbfe-3489-4b79-b850-34d911527c88"),
		NoMatch("false positive 1", "DATABASE_ID=62b0dbfe-3489-4b79-b850-34d911527c88"),
		NoMatch("false positive 2", "PINECONE_API_KEY=00000000-0000-0000-0000-000000000000"),
	},
})

var _ = Add(config.Rule{
	ID:           "pinecone-api-key.2",
	Confidence:   "high",
	Description:  "Pinecone API key version 2 (pcsk format).",
	Regex:        Token(`pcsk_[A-Za-z0-9]{5,6}_[A-Za-z0-9]{63}`),
	Keywords:     []string{"pcsk_"},
	ValidateExpr: pineconeValidateExpr,
	FilterExpr:   MinEntropy(3.5),
	Tests: []config.RuleTest{
		Match("true positive 1", "PINECONE_API_KEY=pcsk_RFbD56_RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klKiz9pyKl17ltLSvQmntzYl", "pcsk_RFbD56_RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klKiz9pyKl17ltLSvQmntzYl"),
		NoMatch("false positive 1", "PINECONE_API_KEY=pcsk_short"),
		NoMatch("false positive 2", "PINECONE_API_KEY=pcsk_abc12_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
	},
})
