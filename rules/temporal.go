package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "temporal-cloud-api-key.1",
	Confidence:  "high",
	Description: "Temporal Cloud API key.",
	Regex: Token(
		`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*Y2NvdW50X2lk[A-Za-z0-9_-]*InRlbXBvcmFsLmlv[A-Za-z0-9_-]*(?:ICJrZXlfaWQiOi|a2V5X2lk|rZXlfaWQi)[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}`,
	),
	Keywords: []string{"inrlbxbvcmfslmlv"},
	ValidateExpr: `let r = http.get("https://saas-api.tmprl.cloud/cloud/current-identity", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 && ((r.body contains "\"user\"") || (r.body contains "\"serviceAccount\"")) ? {
    "result": "valid"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Request not authenticated"
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) < 3.2
|| !matchesAny(finding["secret"], ["^(?:[^0-9]*[0-9]){3}"])`,
	Tests: []config.RuleTest{
		Match("true positive 1", "TEMPORAL_API_KEY=eyJhbGciOiJFUzI1NiIsImtpZCI6IlNhbXBsZSJ9.eyJhY2NvdW50X2lkIjoic2FtcGxlIiwiYXVkIjpbInRlbXBvcmFsLmlvIl0sImlzcyI6InRlbXBvcmFsLmlvIiwia2V5X2lkIjoic2FtcGxlLWtleSIsInN1YiI6InVzZXItMTIzIiwiZXhwIjoyMDAwMDAwMDAwfQ.c2lnbmF0dXJlX3BsYWNlaG9sZGVyXzEyMzQ1Njc4OTA", "eyJhbGciOiJFUzI1NiIsImtpZCI6IlNhbXBsZSJ9.eyJhY2NvdW50X2lkIjoic2FtcGxlIiwiYXVkIjpbInRlbXBvcmFsLmlvIl0sImlzcyI6InRlbXBvcmFsLmlvIiwia2V5X2lkIjoic2FtcGxlLWtleSIsInN1YiI6InVzZXItMTIzIiwiZXhwIjoyMDAwMDAwMDAwfQ.c2lnbmF0dXJlX3BsYWNlaG9sZGVyXzEyMzQ1Njc4OTA"),
		NoMatch("false positive 1", "TEMPORAL_API_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInN1YiI6InVzZXIiLCJleHAiOjE5NzIxNzI0NjF9.WQWcwBAQFNE259f2o8ruFln_UMLTFEnEaUD7KHrs9Aw"),
		NoMatch("false positive 2", "TEMPORAL_API_KEY=eyJshort.payload.signature"),
	},
})
