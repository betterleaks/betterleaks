package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

// The response is keyed by the secret: retain only the selected token value.
// https://raw.githubusercontent.com/lichess-org/api/master/doc/specs/tags/oauth/api-token-test.yaml
const lichessValidateExpr = `let r = http.post("https://lichess.org/api/token/test", {
  "Content-Type": "text/plain", "Accept": "application/json"
}, finding["secret"]);
let body = type(r.json) == "map" ? r.json : {};
let token = body[finding["secret"]];
r.status == 200 && type(token) == "map" && type(token?.userId) == "string" && token.userId != "" ? {
  "result": "valid", "analysis": {
    "user_id": token.userId,
    "scopes": type(token?.scopes) == "string" ? strings.splitTrim(token.scopes, ",") : [],
    "expires_at_ms": type(token?.expires) == "float" ? token.expires : nil
  }
} : r.status == 200 && finding["secret"] in body && token == nil ? {
  "result": "invalid", "reason": "Invalid or expired token"
} : validate.unknown(r)`
const lichessAnalyzeExpr = `let input = validation.analysis;
let scopes = input["scopes"] ?? [];
let capabilities = analysis.capabilities({
  "read": any(scopes, {# in ["study:read", "engine:read", "preference:read", "follow:read", "team:read", "email:read", "challenge:read", "puzzle:read"]}),
  "write": any(scopes, {# in ["study:write", "engine:write", "preference:write", "follow:write", "challenge:write", "challenge:bulk", "tournament:write", "racer:write", "puzzle:write", "msg:write", "board:play", "bot:play", "team:write", "team:lead", "note:write"]})
});
{
  "identity": {"id": input["user_id"] ?? ""},
  "metadata": fromPairs(filter(toPairs({"scopes": scopes, "expires_at_ms": input["expires_at_ms"]}), {#[1] != nil && #[1] != "" && #[1] != []})),
  "capabilities": capabilities
}`

var _ = rulebuilder.Add(config.Rule{
	ID:           "lichess-personal-access-token",
	Confidence:   "high",
	Description:  "Lichess personal access token.",
	Regex:        rulebuilder.Token(`lip_[A-Za-z0-9_]{16,60}`),
	Keywords:     []string{"lip_"},
	ValidateExpr: lichessValidateExpr,
	FilterExpr:   rulebuilder.MinEntropy(3.5),
	AnalyzeExpr:  lichessAnalyzeExpr,
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "LICHESS_TOKEN=lip_eoTtDxpQ4FWYcbMq0Kt5b9ws_pgsxUmO", "lip_eoTtDxpQ4FWYcbMq0Kt5b9ws_pgsxUmO"),
		rulebuilder.NoMatch("false positive 1", "LICHESS_TOKEN=lip_short"),
	},
})
