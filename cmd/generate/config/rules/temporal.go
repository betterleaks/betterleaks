package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
)

func TemporalCloudAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "temporal-cloud-api-key.1",
		Description: "Temporal Cloud API key.",
		Regex: utils.GenerateUniqueTokenRegex(
			`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*Y2NvdW50X2lk[A-Za-z0-9_-]*InRlbXBvcmFsLmlv[A-Za-z0-9_-]*(?:ICJrZXlfaWQiOi|a2V5X2lk|rZXlfaWQi)[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}`,
			false,
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
		Filter: `filter.entropy(finding["secret"]) < 3.2
|| !filter.matchesAny(finding["secret"], ["^(?:[^0-9]*[0-9]){3}"])`,
	}

	// validate
	tps := []string{
		`TEMPORAL_API_KEY=eyJhbGciOiJFUzI1NiIsImtpZCI6IlNhbXBsZSJ9.eyJhY2NvdW50X2lkIjoic2FtcGxlIiwiYXVkIjpbInRlbXBvcmFsLmlvIl0sImlzcyI6InRlbXBvcmFsLmlvIiwia2V5X2lkIjoic2FtcGxlLWtleSIsInN1YiI6InVzZXItMTIzIiwiZXhwIjoyMDAwMDAwMDAwfQ.c2lnbmF0dXJlX3BsYWNlaG9sZGVyXzEyMzQ1Njc4OTA`,
	}
	fps := []string{
		`TEMPORAL_API_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInN1YiI6InVzZXIiLCJleHAiOjE5NzIxNzI0NjF9.WQWcwBAQFNE259f2o8ruFln_UMLTFEnEaUD7KHrs9Aw`,
		`TEMPORAL_API_KEY=eyJshort.payload.signature`,
	}
	return utils.Validate(r, tps, fps)
}
