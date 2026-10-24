package rules

import (
	"encoding/base64"

	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
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

func MapBox() *config.Rule {
	r := config.Rule{
		// Keep the existing public-token ID for configuration compatibility.
		ID:          "mapbox-api-token",
		Description: "Mapbox public access token. Requests can incur charges on the owner's account.",
		Confidence:  "high",
		// The signature encodes 16 bytes. Its last character carries only two bits.
		Regex:    `\b(pk\.eyJ1Ijoi[A-Za-z0-9_-]{15,300}\.[A-Za-z0-9_-]{21}[AQgw])(?:$|[^A-Za-z0-9_-])`,
		Keywords: []string{"pk.eyJ1Ijoi"},
		Tags:     []string{"provider:mapbox", "category:maps"},
		FilterExpr: `let payload = split(finding["secret"], ".")[1];
let padding = (4 - len(payload) % 4) % 4;
entropy(finding["secret"]) < 4 || len(payload) % 4 == 1 ||
 !(fromBase64(replace(replace(payload, "-", "+"), "_", "/") + repeat("=", padding)) matches
   '^\\{"u":"[^"\\\\\\x00-\\x1f]+"\\s*,\\s*"a"\\s*:\\s*"[A-Za-z0-9]+"\\s*\\}$')`,
		ValidateExpr: mapboxValidateExpr,
		AnalyzeExpr:  mapboxAnalyzeExpr,
	}
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"u":"betterleaks-fixture","a":"c1234567890abcdefghijklmn"}`))
	token := "pk." + payload + ".AbCdEfGhIjKlMnOpQrStUQ"
	tps := append(utils.GenerateSampleSecrets("mapbox", token),
		token,
		"machine api.mapbox.com\npassword "+token+"\n",
		"https://api.mapbox.com?access_token="+token+"&limit=1")
	for _, payload := range []string{
		`{"u":"fixture","a":"Ab12Cd3"}`,
		`{"u":"fixture","a":"0123456789abcdef0123456789abcdef"}`,
	} {
		tps = append(tps, "pk."+base64.RawURLEncoding.EncodeToString([]byte(payload))+".AbCdEfGhIjKlMnOpQrStUQ")
	}
	fps := []string{
		"pk.eyJ1Ijoi<your-token>",
		"x" + token,
		token[:len(token)-1],
		token + "A",
		token[:len(token)-1] + "B",
		"tk." + token[3:],
		"pk.eyJ1Ijoi-----------------.AbCdEfGhIjKlMnOpQrStUQ",
	}
	for _, payload := range []string{
		`{"u":"fixture","a":"XXXX-REMOVED-XXXX"}`,
		`{"u":"fixture","a":123456789}`,
		`{"u":"fixture"}`,
		`{"u":"","a":"c1234567890abcdefghijklmn"}`,
		`{"u":"fixture","a":invalid}`,
	} {
		fps = append(fps, "pk."+base64.RawURLEncoding.EncodeToString([]byte(payload))+".AbCdEfGhIjKlMnOpQrStUQ")
	}
	return utils.Validate(r, tps, fps)
}

func MapboxSecretToken() *config.Rule {
	r := config.Rule{
		ID:          "mapbox-secret-token",
		Description: "Mapbox secret access token. Granted scopes may allow uploads, edits, or token management.",
		Confidence:  "high",
		Regex:       `\b(sk\.eyJ1Ijoi[A-Za-z0-9_-]{15,300}\.[A-Za-z0-9_-]{21}[AQgw])(?:$|[^A-Za-z0-9_-])`,
		Keywords:    []string{"sk.eyJ1Ijoi"},
		Tags:        []string{"provider:mapbox", "category:maps"},
		FilterExpr: `let payload = split(finding["secret"], ".")[1];
let padding = (4 - len(payload) % 4) % 4;
entropy(finding["secret"]) < 4 || len(payload) % 4 == 1 ||
 !(fromBase64(replace(replace(payload, "-", "+"), "_", "/") + repeat("=", padding)) matches
   '^\\{"u":"[^"\\\\\\x00-\\x1f]+"\\s*,\\s*"a"\\s*:\\s*"[A-Za-z0-9]+"\\s*\\}$')`,
		ValidateExpr: mapboxValidateExpr,
		AnalyzeExpr:  mapboxAnalyzeExpr,
	}
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"u":"betterleaks-fixture","a":"c1234567890abcdefghijklmn"}`))
	token := "sk." + payload + ".AbCdEfGhIjKlMnOpQrStUQ"
	tps := append(utils.GenerateSampleSecrets("mapbox", token),
		token,
		"machine api.mapbox.com\npassword "+token+"\n",
		"https://api.mapbox.com?access_token="+token+"&limit=1")
	for _, payload := range []string{
		`{"u":"fixture","a":"Ab12Cd3"}`,
		`{"u":"fixture","a":"0123456789abcdef0123456789abcdef"}`,
	} {
		tps = append(tps, "sk."+base64.RawURLEncoding.EncodeToString([]byte(payload))+".AbCdEfGhIjKlMnOpQrStUQ")
	}
	fps := []string{
		"sk.eyJ1Ijoi<your-token>",
		"x" + token,
		token[:len(token)-1],
		token + "A",
		token[:len(token)-1] + "B",
		"tk." + token[3:],
		"sk.eyJ1Ijoi-----------------.AbCdEfGhIjKlMnOpQrStUQ",
	}
	for _, payload := range []string{
		`{"u":"fixture","a":"XXXX-REMOVED-XXXX"}`,
		`{"u":"fixture","a":123456789}`,
		`{"u":"fixture"}`,
		`{"u":"","a":"c1234567890abcdefghijklmn"}`,
		`{"u":"fixture","a":invalid}`,
	} {
		fps = append(fps, "sk."+base64.RawURLEncoding.EncodeToString([]byte(payload))+".AbCdEfGhIjKlMnOpQrStUQ")
	}
	return utils.Validate(r, tps, fps)
}
