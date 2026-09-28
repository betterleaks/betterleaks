package rules

// Self-profile responses identify an owner without proving effective resource
// permissions. Each validator allowlists identity and metadata fields before
// placing them in the private handoff; no response payload is copied wholesale.
const identityOnlyAnalyzeExpr = `let input = validation.analysis;
{
  "identity": input["identity"] ?? {},
  "metadata": input["metadata"] ?? {},
  "capabilities": [],
  "reason": "Identity resolved; effective permissions were not returned"
}`
