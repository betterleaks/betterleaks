package rules

import "github.com/betterleaks/betterleaks/v2/config"

const tailscaleVerifyExpr = `let parts = split(finding["secret"], "-");
let r = http.post("https://api.tailscale.com/api/v2/secret-scanning/verify", {
  "Content-Type": "application/x-www-form-urlencoded",
  "Accept": "application/json"
}, "key=" + finding["secret"]);
r.status == 204 ? {
  "result": "valid",
  "analysis": {"metadata": {"key_id": parts[len(parts) - 2]}}
} : r.status == 401 ? {
  "result": "invalid", "reason": "Invalid or expired Tailscale key"
} : validate.unknown(r)`

const tailscaleVerifyAnalyzeExpr = `{
  "metadata": validation.analysis["metadata"] ?? {},
  "capabilities": [],
  "reason": "Key verified; owner and effective permissions were not returned"
}`

// https://tailscale.com/docs/features/oauth-clients
const tailscaleAPIValidateExpr = `let parts = split(finding["secret"], "-");
let key_id = parts[len(parts) - 2];
let r = http.get("https://api.tailscale.com/api/v2/tailnet/-/keys/" + key_id, {
  "Authorization": "Bearer " + finding["secret"],
  "Accept": "application/json"
});
r.status == 200 && type(r.json) == "map" && (r.json?.id ?? "") == key_id ? {
  "result": "valid",
  "analysis": {
    "user_id": string(r.json?.userId ?? ""),
    "scopes": r.json?.scopes ?? [],
    "metadata": {
      "key_id": key_id,
      "key_type": r.json?.keyType ?? "",
      "description": r.json?.description ?? "",
      "created": r.json?.created ?? "",
      "expires": r.json?.expires ?? ""
    }
  }
} : r.status == 403 ? {
  "result": "valid",
  "reason": "Authenticated but key metadata is forbidden",
  "analysis": {"metadata": {"key_id": key_id}}
} : r.status == 401 ? {
  "result": "invalid", "reason": "Invalid or expired Tailscale API token"
} : validate.unknown(r)`

// https://tailscale.com/docs/features/oauth-clients#tailscale-oauth-token-endpoint
const tailscaleOAuthValidateExpr = `let parts = split(finding["secret"], "-");
let client_id = parts[len(parts) - 2];
let r = http.post("https://api.tailscale.com/api/v2/oauth/token", {
  "Content-Type": "application/x-www-form-urlencoded",
  "Accept": "application/json"
}, "grant_type=client_credentials&client_id=" + client_id + "&client_secret=" + finding["secret"]);
r.status == 200 && type(r.json) == "map" && type(r.json?.access_token) == "string" && (r.json?.access_token ?? "") != "" ? {
  "result": "valid",
  "analysis": {
    "scopes": strings.splitTrim(r.json?.scope ?? "", " "),
    "metadata": {
      "client_id": client_id,
      "token_type": r.json?.token_type ?? "",
      "token_ttl_seconds": r.json?.expires_in ?? 0
    }
  }
} : r.status == 401 ? {
  "result": "invalid", "reason": "Invalid Tailscale OAuth client secret"
} : validate.unknown(r)`

// https://tailscale.com/docs/reference/trust-credentials#scopes
const tailscaleScopesAnalyzeExpr = `let input = validation.analysis;
let scopes = input["scopes"] ?? [];
let writable = ["all", "acl", "devices", "dns", "routes", "policy_file", "devices:core", "devices:posture_attributes", "devices:routes", "devices_invites", "api_access_tokens", "auth_keys", "oauth_keys", "federated_keys", "webhooks", "log_streaming", "logs:network", "account_settings", "feature_settings"];
let readable = ["all:read", "acl:read", "devices:read", "dns:read", "routes:read", "logs:read", "policy_file:read", "devices:core:read", "devices:posture_attributes:read", "devices:routes:read", "devices_invites:read", "api_access_tokens:read", "auth_keys:read", "oauth_keys:read", "federated_keys:read", "webhooks:read", "log_streaming:read", "logs:configuration:read", "logs:network:read", "account_settings:read", "feature_settings:read"];
{
  "reason": len(scopes) == 0 ? "Tailscale did not return scope metadata" :
    !intersects(scopes, writable) && !intersects(scopes, readable) ? "Tailscale returned no recognized scopes" : "",
  "identity": {"id": input["user_id"] ?? ""},
  "metadata": {
    "key_id": input["metadata"]?.key_id ?? "",
    "key_type": input["metadata"]?.key_type ?? "",
    "description": input["metadata"]?.description ?? "",
    "created": input["metadata"]?.created ?? "",
    "expires": input["metadata"]?.expires ?? "",
    "client_id": input["metadata"]?.client_id ?? "",
    "token_type": input["metadata"]?.token_type ?? "",
    "token_ttl_seconds": input["metadata"]?.token_ttl_seconds ?? 0,
    "scopes": scopes
  },
  "capabilities": analysis.capabilities({
    "read": intersects(scopes, readable) || intersects(scopes, writable),
    "write": intersects(scopes, writable),
    "create_credentials": intersects(scopes, ["all", "auth_keys", "devices", "webhooks"]),
    "manage_users": "all" in scopes,
    "admin": "all" in scopes
  })
}`

// https://tailscale.com/docs/reference/key-prefixes
var _ = Add(config.Rule{
	ID:           "tailscale-api-key.1",
	Confidence:   "high",
	Description:  "Tailscale API access token.",
	Regex:        `\b(tskey-api-k[A-Za-z0-9]{4,16}CNTRL-[A-Za-z0-9]{28,40})\b`,
	Keywords:     []string{"tskey-api-k"},
	Tags:         []string{"provider:tailscale"},
	ValidateExpr: tailscaleAPIValidateExpr,
	AnalyzeExpr:  tailscaleScopesAnalyzeExpr,
	FilterExpr:   MinEntropy(3.5),
	Tests: []config.RuleTest{
		Match("true positive 1", "TAILSCALE_API_KEY=tskey-api-kRFbDCNTRL-RFbD56TI2smTyVsGd5Xav0yu99ZA", "tskey-api-kRFbDCNTRL-RFbD56TI2smTyVsGd5Xav0yu99ZA"),
		Match("bare secret", "tskey-api-kRFbD56TI2smTyVsGCNTRL-RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575k", "tskey-api-kRFbD56TI2smTyVsGCNTRL-RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575k"),
		NoMatch("false positive 1", "TAILSCALE_API_KEY=tskey-api-short"),
		NoMatch("false positive 2", "tskey-api-kAb12CNTRL-0123456789ABCDEFGHIJKLMNOPQ"),
		NoMatch("false positive 3", "tskey-api-kAb12CNTRL-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcde"),
		NoMatch("false positive 4", "tskey-auth-kAb12CNTRL-0123456789ABCDEFGHIJKLMNOPQR"),
	},
})

var _ = Add(config.Rule{
	ID:           "tailscale-auth-key",
	Confidence:   "high",
	Description:  "Tailscale device enrollment key.",
	Regex:        `\b(tskey-auth-k[A-Za-z0-9]{4,16}CNTRL-[A-Za-z0-9]{28,40})\b`,
	Keywords:     []string{"tskey-auth-k"},
	Tags:         []string{"provider:tailscale"},
	ValidateExpr: tailscaleVerifyExpr,
	AnalyzeExpr:  tailscaleVerifyAnalyzeExpr,
	FilterExpr:   MinEntropy(3.5),
	Tests: []config.RuleTest{
		Match("tailscale assignment", `tailscaleToken = "tskey-auth-kRFbD56TI2smTCNTRL-RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA"`, "tskey-auth-kRFbD56TI2smTCNTRL-RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA"),
		NoMatch("false positive 1", "tskey-auth-short"),
	},
})

var _ = Add(config.Rule{
	ID:           "tailscale-oauth-client-secret",
	Confidence:   "high",
	Description:  "Tailscale OAuth credential for minting scoped API tokens.",
	Regex:        `\b(tskey-client-k[A-Za-z0-9]{4,16}CNTRL-[A-Za-z0-9]{28,40})\b`,
	Keywords:     []string{"tskey-client-k"},
	Tags:         []string{"provider:tailscale", "category:oauth"},
	ValidateExpr: tailscaleOAuthValidateExpr,
	AnalyzeExpr:  tailscaleScopesAnalyzeExpr,
	FilterExpr:   MinEntropy(3.5),
	Tests: []config.RuleTest{
		Match("tailscale assignment", `tailscaleToken = "tskey-client-kRFbD56TI2smTCNTRL-RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA"`, "tskey-client-kRFbD56TI2smTCNTRL-RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA"),
		NoMatch("false positive 1", "tskey-client-short"),
	},
})

var _ = Add(config.Rule{
	ID:          "tailscale-scim-key",
	Confidence:  "high",
	Description: "Tailscale user provisioning credential.",
	// The SCIM key ID format is undocumented.
	Regex:        `\b(tskey-scim-[A-Za-z0-9]{8,24}-[A-Za-z0-9]{28,40})\b`,
	Keywords:     []string{"tskey-scim-"},
	Tags:         []string{"provider:tailscale"},
	ValidateExpr: tailscaleVerifyExpr,
	AnalyzeExpr:  tailscaleVerifyAnalyzeExpr,
	FilterExpr:   MinEntropy(3.5),
	Tests: []config.RuleTest{
		Match("tailscale assignment", `tailscaleToken = "tskey-scim-RFbD56TI2smTyVsG-RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA"`, "tskey-scim-RFbD56TI2smTyVsG-RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA"),
		NoMatch("false positive 1", "tskey-scim-short"),
	},
})

var _ = Add(config.Rule{
	ID:           "tailscale-webhook-secret",
	Confidence:   "high",
	Description:  "Tailscale webhook signing secret.",
	Regex:        `\b(tskey-webhook-k[A-Za-z0-9]{4,16}CNTRL-[A-Za-z0-9]{28,40})\b`,
	Keywords:     []string{"tskey-webhook-k"},
	Tags:         []string{"provider:tailscale"},
	ValidateExpr: tailscaleVerifyExpr,
	AnalyzeExpr:  tailscaleVerifyAnalyzeExpr,
	FilterExpr:   MinEntropy(3.5),
	Tests: []config.RuleTest{
		Match("tailscale assignment", `tailscaleToken = "tskey-webhook-kRFbD56TI2smTCNTRL-RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA"`, "tskey-webhook-kRFbD56TI2smTCNTRL-RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA"),
		NoMatch("false positive 1", "tskey-webhook-short"),
	},
})

// Untyped keys predate the distinction between auth keys and API tokens.
var _ = Add(config.Rule{
	ID:           "tailscale-key",
	Confidence:   "high",
	Description:  "Tailscale legacy untyped credential.",
	Regex:        `\b(tskey-k[A-Za-z0-9]{4,16}CNTRL-[A-Za-z0-9]{20,40})\b`,
	Keywords:     []string{"tskey-k"},
	Tags:         []string{"provider:tailscale"},
	ValidateExpr: tailscaleVerifyExpr,
	AnalyzeExpr:  tailscaleVerifyAnalyzeExpr,
	FilterExpr:   MinEntropy(3.5),
	Tests: []config.RuleTest{
		Match("tailscale assignment", `tailscaleToken = "tskey-kRFbD56TI2smTCNTRL-RFbD56TI2smTyVsGd5Xa"`, "tskey-kRFbD56TI2smTCNTRL-RFbD56TI2smTyVsGd5Xa"),
		NoMatch("false positive 1", "tskey-short"),
	},
})
