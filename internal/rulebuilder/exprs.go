package rulebuilder

import "fmt"

// Expressions shared by provider filters, validators, and analyzers.

func MinEntropy(threshold float64) string {
	return fmt.Sprintf(`entropy(finding["secret"]) < %.1f`, threshold)
}

const MinEntropyAndTokenEfficiency = `entropy(finding["secret"]) < 3.0 || tokenRatio(finding["secret"]) >= 2.5`

func BearerGetValidationExpr(url string, successCheck string) string {
	return `let r = http.get("` + url + `", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  });
r.status == 200 && (` + successCheck + `) ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)
`
}

// IdentityOnlyAnalyzeExpr analyzes self-profile responses, which identify an
// owner without proving effective resource permissions. Each validator
// allowlists identity and metadata fields before placing them in the private
// handoff; no response payload is copied wholesale.
const IdentityOnlyAnalyzeExpr = `let input = validation.analysis;
{
  "identity": input["identity"] ?? {},
  "metadata": input["metadata"] ?? {},
  "capabilities": [],
  "reason": "Identity resolved; effective permissions were not returned"
}`
