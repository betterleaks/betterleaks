package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
)

// The retrieval endpoint returns HTTP 200 for both valid and rejected tokens.
// https://docs.mapbox.com/api/accounts/tokens/#retrieve-a-token
const mapboxValidateExpr = `let r = http.get("https://api.mapbox.com/tokens/v2?access_token=" + strings.urlQueryEscape(finding["secret"]), {"Accept": "application/json"});
let body = type(r.json) == "map" ? r.json : {};
let code = body.code ?? "";
let token = type(body.token) == "map" ? body.token : {};
r.status == 200 && code == "TokenValid" ? {
 "result": "valid", "reason": code,
 "analysis": {
  "username": type(token.user) == "string" ? token.user : "",
  "token_id": type(token.authorization) == "string" ? token.authorization : "",
  "usage": type(token.usage) == "string" ? token.usage : ""
 }
} : r.status == 200 && code in ["TokenRevoked", "TokenExpired"] ? {
 "result": "revoked", "reason": code
} : r.status == 200 && code in ["TokenInvalid", "TokenMalformed"] ? {
 "result": "invalid", "reason": code
} : r.status == 401 && type(body.message) == "string" && body.message != "" ? {
 "result": "invalid", "reason": "401 Unauthorized: " + body.message
} : validate.unknown(r)`

// Scope lookup is analysis-only: missing tokens:read must not invalidate a token.
// Inspect only the first page to bound optional metadata requests.
const mapboxAnalyzeExpr = `let input = validation.analysis;
let username = input["username"] ?? "";
let token_id = input["token_id"] ?? "";
let usage = input["usage"] ?? "";
let r = usage == "sk" && username matches "^[A-Za-z0-9_-]+$" && token_id != "" ?
 http.get("https://api.mapbox.com/tokens/v2/" + username + "?access_token=" + strings.urlQueryEscape(finding["secret"]) + "&usage=sk&limit=100", {"Accept": "application/json"}) : {};
let tokens = (r.status ?? 0) == 200 && type(r.json) == "array" ? r.json : [];
let token = find(tokens, {type(#) == "map" && (#.id ?? "") == token_id});
{
 "identity": {"username": username},
 "metadata": {
  "token_id": token_id,
  "usage": usage,
  "note": type(token?.note) == "string" ? token.note : "",
  "scopes": type(token?.scopes) == "array" ? filter(token.scopes, {type(#) == "string"}) : []
 }
}`

var _ = Add(config.Rule{
	// Keep the existing public-token ID for configuration compatibility.
	ID:          "mapbox-api-token",
	Description: "Mapbox public access token. Requests can incur charges on the owner's account.",
	Confidence:  "high",
	// The signature encodes 16 bytes. Its last character carries only two bits.
	Regex:    `\b(pk\.eyJ1Ijoi[A-Za-z0-9_-]{15,300}\.[A-Za-z0-9_-]{21}[AQgw])(?:$|[^A-Za-z0-9_-])`,
	Keywords: []string{"pk.eyJ1Ijoi"},
	Tags:     []string{"provider:mapbox", "category:maps"},
	FilterExpr: `let parts = split(finding["secret"], ".");
let payload = len(parts) == 3 ? parts[1] : "";
let padding = (4 - len(payload) % 4) % 4;
entropy(finding["secret"]) < 4 || len(payload) % 4 == 1 ||
 !(fromBase64(replace(replace(payload, "-", "+"), "_", "/") + repeat("=", padding)) matches
   '^\\{"u":"[^"\\\\\\x00-\\x1f]+"\\s*,\\s*"a"\\s*:\\s*"[A-Za-z0-9]+"\\s*\\}$')`,
	ValidateExpr: mapboxValidateExpr,
	AnalyzeExpr:  mapboxAnalyzeExpr,
	Tests: []config.RuleTest{
		Match("mapbox assignment", `mapboxToken = "pk.eyJ1IjoiYmV0dGVybGVha3MtZml4dHVyZSIsImEiOiJjMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1uIn0.AbCdEfGhIjKlMnOpQrStUQ"`, "pk.eyJ1IjoiYmV0dGVybGVha3MtZml4dHVyZSIsImEiOiJjMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1uIn0.AbCdEfGhIjKlMnOpQrStUQ"),
		Match("bare secret", "pk.eyJ1IjoiYmV0dGVybGVha3MtZml4dHVyZSIsImEiOiJjMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1uIn0.AbCdEfGhIjKlMnOpQrStUQ", "pk.eyJ1IjoiYmV0dGVybGVha3MtZml4dHVyZSIsImEiOiJjMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1uIn0.AbCdEfGhIjKlMnOpQrStUQ"),
		Match("true positive 1", "machine api.mapbox.com\npassword pk.eyJ1IjoiYmV0dGVybGVha3MtZml4dHVyZSIsImEiOiJjMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1uIn0.AbCdEfGhIjKlMnOpQrStUQ\n", "pk.eyJ1IjoiYmV0dGVybGVha3MtZml4dHVyZSIsImEiOiJjMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1uIn0.AbCdEfGhIjKlMnOpQrStUQ"),
		Match("true positive 2", "https://api.mapbox.com?access_token=pk.eyJ1IjoiYmV0dGVybGVha3MtZml4dHVyZSIsImEiOiJjMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1uIn0.AbCdEfGhIjKlMnOpQrStUQ&limit=1", "pk.eyJ1IjoiYmV0dGVybGVha3MtZml4dHVyZSIsImEiOiJjMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1uIn0.AbCdEfGhIjKlMnOpQrStUQ"),
		Match("bare secret 2", "pk.eyJ1IjoiZml4dHVyZSIsImEiOiJBYjEyQ2QzIn0.AbCdEfGhIjKlMnOpQrStUQ", "pk.eyJ1IjoiZml4dHVyZSIsImEiOiJBYjEyQ2QzIn0.AbCdEfGhIjKlMnOpQrStUQ"),
		Match("bare secret 3", "pk.eyJ1IjoiZml4dHVyZSIsImEiOiIwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZiJ9.AbCdEfGhIjKlMnOpQrStUQ", "pk.eyJ1IjoiZml4dHVyZSIsImEiOiIwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZiJ9.AbCdEfGhIjKlMnOpQrStUQ"),
		NoMatch("false positive 1", "pk.eyJ1Ijoi<your-token>"),
		NoMatch("false positive 2", "xpk.eyJ1IjoiYmV0dGVybGVha3MtZml4dHVyZSIsImEiOiJjMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1uIn0.AbCdEfGhIjKlMnOpQrStUQ"),
		NoMatch("false positive 3", "pk.eyJ1IjoiYmV0dGVybGVha3MtZml4dHVyZSIsImEiOiJjMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1uIn0.AbCdEfGhIjKlMnOpQrStU"),
		NoMatch("false positive 4", "pk.eyJ1IjoiYmV0dGVybGVha3MtZml4dHVyZSIsImEiOiJjMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1uIn0.AbCdEfGhIjKlMnOpQrStUQA"),
		NoMatch("false positive 5", "pk.eyJ1IjoiYmV0dGVybGVha3MtZml4dHVyZSIsImEiOiJjMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1uIn0.AbCdEfGhIjKlMnOpQrStUB"),
		NoMatch("false positive 6", "tk.eyJ1IjoiYmV0dGVybGVha3MtZml4dHVyZSIsImEiOiJjMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1uIn0.AbCdEfGhIjKlMnOpQrStUQ"),
		NoMatch("false positive 7", "pk.eyJ1Ijoi-----------------.AbCdEfGhIjKlMnOpQrStUQ"),
		NoMatch("false positive 8", "pk.eyJ1IjoiZml4dHVyZSIsImEiOiJYWFhYLVJFTU9WRUQtWFhYWCJ9.AbCdEfGhIjKlMnOpQrStUQ"),
		NoMatch("false positive 9", "pk.eyJ1IjoiZml4dHVyZSIsImEiOjEyMzQ1Njc4OX0.AbCdEfGhIjKlMnOpQrStUQ"),
		NoMatch("false positive 10", "pk.eyJ1IjoiZml4dHVyZSJ9.AbCdEfGhIjKlMnOpQrStUQ"),
		NoMatch("false positive 11", "pk.eyJ1IjoiIiwiYSI6ImMxMjM0NTY3ODkwYWJjZGVmZ2hpamtsbW4ifQ.AbCdEfGhIjKlMnOpQrStUQ"),
		NoMatch("false positive 12", "pk.eyJ1IjoiZml4dHVyZSIsImEiOmludmFsaWR9.AbCdEfGhIjKlMnOpQrStUQ"),
	},
})

var _ = Add(config.Rule{
	ID:          "mapbox-secret-token",
	Description: "Mapbox secret access token. Granted scopes may allow uploads, edits, or token management.",
	Confidence:  "high",
	Regex:       `\b(sk\.eyJ1Ijoi[A-Za-z0-9_-]{15,300}\.[A-Za-z0-9_-]{21}[AQgw])(?:$|[^A-Za-z0-9_-])`,
	Keywords:    []string{"sk.eyJ1Ijoi"},
	Tags:        []string{"provider:mapbox", "category:maps"},
	FilterExpr: `let parts = split(finding["secret"], ".");
let payload = len(parts) == 3 ? parts[1] : "";
let padding = (4 - len(payload) % 4) % 4;
entropy(finding["secret"]) < 4 || len(payload) % 4 == 1 ||
 !(fromBase64(replace(replace(payload, "-", "+"), "_", "/") + repeat("=", padding)) matches
   '^\\{"u":"[^"\\\\\\x00-\\x1f]+"\\s*,\\s*"a"\\s*:\\s*"[A-Za-z0-9]+"\\s*\\}$')`,
	ValidateExpr: mapboxValidateExpr,
	AnalyzeExpr:  mapboxAnalyzeExpr,
	Tests: []config.RuleTest{
		Match("mapbox assignment", `mapboxToken = "sk.eyJ1IjoiYmV0dGVybGVha3MtZml4dHVyZSIsImEiOiJjMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1uIn0.AbCdEfGhIjKlMnOpQrStUQ"`, "sk.eyJ1IjoiYmV0dGVybGVha3MtZml4dHVyZSIsImEiOiJjMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1uIn0.AbCdEfGhIjKlMnOpQrStUQ"),
		Match("bare secret", "sk.eyJ1IjoiYmV0dGVybGVha3MtZml4dHVyZSIsImEiOiJjMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1uIn0.AbCdEfGhIjKlMnOpQrStUQ", "sk.eyJ1IjoiYmV0dGVybGVha3MtZml4dHVyZSIsImEiOiJjMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1uIn0.AbCdEfGhIjKlMnOpQrStUQ"),
		Match("true positive 1", "machine api.mapbox.com\npassword sk.eyJ1IjoiYmV0dGVybGVha3MtZml4dHVyZSIsImEiOiJjMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1uIn0.AbCdEfGhIjKlMnOpQrStUQ\n", "sk.eyJ1IjoiYmV0dGVybGVha3MtZml4dHVyZSIsImEiOiJjMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1uIn0.AbCdEfGhIjKlMnOpQrStUQ"),
		Match("true positive 2", "https://api.mapbox.com?access_token=sk.eyJ1IjoiYmV0dGVybGVha3MtZml4dHVyZSIsImEiOiJjMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1uIn0.AbCdEfGhIjKlMnOpQrStUQ&limit=1", "sk.eyJ1IjoiYmV0dGVybGVha3MtZml4dHVyZSIsImEiOiJjMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1uIn0.AbCdEfGhIjKlMnOpQrStUQ"),
		Match("bare secret 2", "sk.eyJ1IjoiZml4dHVyZSIsImEiOiJBYjEyQ2QzIn0.AbCdEfGhIjKlMnOpQrStUQ", "sk.eyJ1IjoiZml4dHVyZSIsImEiOiJBYjEyQ2QzIn0.AbCdEfGhIjKlMnOpQrStUQ"),
		Match("bare secret 3", "sk.eyJ1IjoiZml4dHVyZSIsImEiOiIwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZiJ9.AbCdEfGhIjKlMnOpQrStUQ", "sk.eyJ1IjoiZml4dHVyZSIsImEiOiIwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZiJ9.AbCdEfGhIjKlMnOpQrStUQ"),
		NoMatch("false positive 1", "sk.eyJ1Ijoi<your-token>"),
		NoMatch("false positive 2", "xsk.eyJ1IjoiYmV0dGVybGVha3MtZml4dHVyZSIsImEiOiJjMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1uIn0.AbCdEfGhIjKlMnOpQrStUQ"),
		NoMatch("false positive 3", "sk.eyJ1IjoiYmV0dGVybGVha3MtZml4dHVyZSIsImEiOiJjMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1uIn0.AbCdEfGhIjKlMnOpQrStU"),
		NoMatch("false positive 4", "sk.eyJ1IjoiYmV0dGVybGVha3MtZml4dHVyZSIsImEiOiJjMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1uIn0.AbCdEfGhIjKlMnOpQrStUQA"),
		NoMatch("false positive 5", "sk.eyJ1IjoiYmV0dGVybGVha3MtZml4dHVyZSIsImEiOiJjMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1uIn0.AbCdEfGhIjKlMnOpQrStUB"),
		NoMatch("false positive 6", "tk.eyJ1IjoiYmV0dGVybGVha3MtZml4dHVyZSIsImEiOiJjMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1uIn0.AbCdEfGhIjKlMnOpQrStUQ"),
		NoMatch("false positive 7", "sk.eyJ1Ijoi-----------------.AbCdEfGhIjKlMnOpQrStUQ"),
		NoMatch("false positive 8", "sk.eyJ1IjoiZml4dHVyZSIsImEiOiJYWFhYLVJFTU9WRUQtWFhYWCJ9.AbCdEfGhIjKlMnOpQrStUQ"),
		NoMatch("false positive 9", "sk.eyJ1IjoiZml4dHVyZSIsImEiOjEyMzQ1Njc4OX0.AbCdEfGhIjKlMnOpQrStUQ"),
		NoMatch("false positive 10", "sk.eyJ1IjoiZml4dHVyZSJ9.AbCdEfGhIjKlMnOpQrStUQ"),
		NoMatch("false positive 11", "sk.eyJ1IjoiIiwiYSI6ImMxMjM0NTY3ODkwYWJjZGVmZ2hpamtsbW4ifQ.AbCdEfGhIjKlMnOpQrStUQ"),
		NoMatch("false positive 12", "sk.eyJ1IjoiZml4dHVyZSIsImEiOmludmFsaWR9.AbCdEfGhIjKlMnOpQrStUQ"),
	},
})
