package rules

import (
	"fmt"
	"strings"

	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/config"
)

// Composio issues three kinds of API key over the same alphabet and differing
// only in prefix and body length. `oak_` and `uak_` contain `ak_`, so every
// pattern needs a leading boundary or an org or user key is also reported as a
// project key. The trailing boundary cannot be `\b`, because `-` is in the
// alphabet but is not a word character, so a key ending in `-` would be missed.
const composioKeyAlphabet = `[A-Za-z0-9_-]`

// composioKeyRegex pins both boundaries. The leading `\b` is zero-width, so two
// adjacent keys separated by one delimiter are both reported.
func composioKeyRegex(prefix string, bodyLen int) string {
	return fmt.Sprintf(`\b(%s%s{%d})(?:$|[^A-Za-z0-9_-])`, prefix, composioKeyAlphabet, bodyLen)
}

// Composio rejects a live key sent under the wrong header exactly as it rejects
// an unknown one, so each kind has its own endpoint and header.
// https://docs.composio.dev/api-reference
const (
	composioAPIBase          = "https://backend.composio.dev"
	composioProjectVerifyURL = composioAPIBase + "/api/v3/toolkits/categories"
	composioOrgVerifyURL     = composioAPIBase + "/api/v3/org/owner/project/list?limit=1"
	composioUserVerifyURL    = composioAPIBase + "/api/v3/org/list?limit=1"
	composioRevokeURL        = composioAPIBase + "/api/v3.1/api_key_revocation"
)

// composioDeadKeyExpr is the verdict that a key is no longer usable. Composio
// returns 401 for an unknown key, an expired key and a malformed key alike, so
// the verdict comes from `error.slug` rather than the status on its own. The
// org endpoint reports the generic `HTTP_Unauthorized`, which is only decisive
// when the message names the header.
const composioDeadKeyExpr = `r.status == 401 && (
    slug in ["APIKey_InvalidAPIKey", "APIKey_APIKeyExpired", "UserApiKey_Unauthorized"] ||
    (slug == "HTTP_Unauthorized" && startsWithAny(message, ["Invalid x-org-api-key"]))
  )`

// composioValidateExpr asks the key's own endpoint whether it still
// authenticates. A 403 counts as live only when it carries Composio's error
// envelope, identified by a slug and the numeric code that accompanies it; a
// 403 from a gateway, JSON or not, says nothing about the key.
func composioValidateExpr(verifyURL, header string) string {
	return `let r = http.get("` + verifyURL + `", {
    "` + header + `": finding["secret"],
    "Accept": "application/json"
  });
let slug = r.json?.error?.slug ?? "";
let message = r.json?.error?.message ?? "";
r.status == 200 ? {
  "result": "valid"
} : ` + composioDeadKeyExpr + ` ? {
  "result": "invalid",
  "reason": "Composio rejected the key"
} : r.status == 401 && slug == "Auth_Unauthorized" && containsAny(message, ["IP allowlist"]) ? {
  "result": "valid",
  "reason": "Key authenticates but calls are restricted to an IP allowlist",
  "metadata": {"restriction": "ip_allowlist"}
} : r.status == 403 && slug != "" && r.json?.error?.code != nil ? {
  "result": "valid",
  "reason": "Key authenticates but the request was forbidden",
  "metadata": {"restriction": slug}
} : validate.unknown(r)`
}

// composioRevokeExpr posts the key to Composio's public kill switch, then asks
// the key's endpoint whether it still authenticates. Composio revokes a matched
// key before it answers, but the response is a constant {"received": true} that
// deliberately does not reveal whether any submitted key matched, so acceptance
// alone cannot report `revoked`. The follow-up rejection is that evidence. A 500
// means at least one key was not revoked and the request should be retried.
// https://docs.composio.dev/reference/api-reference/api-keys/postApiKeyRevocation
func composioRevokeExpr(verifyURL, header string) string {
	return `let posted = http.post("` + composioRevokeURL + `", {
    "Content-Type": "application/json",
    "Accept": "application/json"
  }, "{\"api_keys\":[" + toJSON(finding["secret"]) + "]}");
posted.status != 200 ? revoke.unknown(posted) : (
  let r = http.get("` + verifyURL + `", {
      "` + header + `": finding["secret"],
      "Accept": "application/json"
    });
  let slug = r.json?.error?.slug ?? "";
  let message = r.json?.error?.message ?? "";
  ` + composioDeadKeyExpr + ` ? {
    "result": "revoked",
    "reason": "Composio rejected the key after revocation"
  } : r.status == 200 ? {
    "result": "unknown",
    "reason": "Composio accepted the revocation but the key still authenticates"
  } : revoke.unknown(r)
)`
}

func ComposioProjectAPIKey() *config.Rule {
	r := config.Rule{
		ID:         "composio-project-api-key",
		Confidence: "high",
		Description: "Detected a Composio project API key, which may expose a project's " +
			"tools, connected accounts and triggers.",
		Regex:        composioKeyRegex(`ak_`, 20),
		Keywords:     []string{"ak_"},
		ValidateExpr: composioValidateExpr(composioProjectVerifyURL, "x-api-key"),
		RevokeExpr:   composioRevokeExpr(composioProjectVerifyURL, "x-api-key"),
		FilterExpr:   utils.MinEntropy(3.0),
	}

	return utils.Validate(r,
		[]string{
			`COMPOSIO_API_KEY="ak_jI60uPF6adMkCuBFESjq"`,
			// A key may end in `-`, which is not a word character.
			`COMPOSIO_API_KEY=ak_Qbez9ytnft9XyXAGPL0-,`,
		},
		[]string{
			// `oak_` and `uak_` both contain `ak_` and must not match here.
			`COMPOSIO_API_KEY="oak_iuGvTZ4eiiy3umBWjwTt"`,
			`COMPOSIO_API_KEY="uak_TRFvy_o-mFznI3IyljByM5LL-SudKFv47vULpKuK2ai"`,
			`COMPOSIO_API_KEY="ak_` + strings.Repeat("a", 19) + `"`,
			`COMPOSIO_API_KEY="ak_` + strings.Repeat("a", 21) + `"`,
			`COMPOSIO_API_KEY="ak_` + strings.Repeat("x", 20) + `"`,
			`COMPOSIO_API_KEY="ak_test"`,
		},
	)
}

func ComposioOrgAPIKey() *config.Rule {
	r := config.Rule{
		ID:         "composio-org-api-key",
		Confidence: "high",
		Description: "Detected a Composio organization API key, which may expose every " +
			"project in the organization.",
		Regex:        composioKeyRegex(`oak_`, 20),
		Keywords:     []string{"oak_"},
		ValidateExpr: composioValidateExpr(composioOrgVerifyURL, "x-org-api-key"),
		RevokeExpr:   composioRevokeExpr(composioOrgVerifyURL, "x-org-api-key"),
		FilterExpr:   utils.MinEntropy(3.0),
	}

	return utils.Validate(r,
		[]string{
			`COMPOSIO_ORG_API_KEY="oak_iuGvTZ4eiiy3umBWjwTt"`,
		},
		[]string{
			`COMPOSIO_ORG_API_KEY="oak_` + strings.Repeat("a", 19) + `"`,
			`COMPOSIO_ORG_API_KEY="oak_` + strings.Repeat("a", 21) + `"`,
			`COMPOSIO_ORG_API_KEY="oak_` + strings.Repeat("y", 20) + `"`,
		},
	)
}

func ComposioUserAPIKey() *config.Rule {
	r := config.Rule{
		ID:         "composio-user-api-key",
		Confidence: "high",
		Description: "Detected a Composio user API key, which may expose the " +
			"organizations and projects the user can reach.",
		Regex:        composioKeyRegex(`uak_`, 43),
		Keywords:     []string{"uak_"},
		ValidateExpr: composioValidateExpr(composioUserVerifyURL, "x-user-api-key"),
		RevokeExpr:   composioRevokeExpr(composioUserVerifyURL, "x-user-api-key"),
		FilterExpr:   utils.MinEntropy(3.0),
	}

	return utils.Validate(r,
		[]string{
			`COMPOSIO_USER_API_KEY="uak_TRFvy_o-mFznI3IyljByM5LL-SudKFv47vULpKuK2ai"`,
		},
		[]string{
			`COMPOSIO_USER_API_KEY="uak_` + strings.Repeat("a", 42) + `"`,
			`COMPOSIO_USER_API_KEY="uak_` + strings.Repeat("a", 44) + `"`,
			`COMPOSIO_USER_API_KEY="uak_` + strings.Repeat("z", 43) + `"`,
		},
	)
}
