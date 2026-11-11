package rules

import "github.com/betterleaks/betterleaks/v2/config"

const githubTokenExpr = `let base_url = env.getOrDefault("GITHUB_BASE_URL", "https://api.github.com"); (let r = http.get(base_url + "/user", {
      "Accept": "application/vnd.github+json",
      "Authorization": "token " + finding["secret"]
    }); r.status == 200 && (r.json?.login ?? "") != "" ? {
      "result": "valid",
      "analysis": {
        "id": r.json?.id != nil ? string(int(r.json.id)) : "",
        "username": (r.json?.login ?? ""),
        "name": (r.json?.name ?? ""),
        "email": (r.json?.email ?? ""),
        "url": (r.json?.html_url ?? ""),
        "account_type": (r.json?.type ?? ""),
        "site_admin": r.json?.site_admin,
        "company": (r.json?.company ?? ""),
        "location": (r.json?.location ?? ""),
        "ldap_dn": (r.json?.ldap_dn ?? ""),
        "expires_at": (r.headers["github-authentication-token-expiration"] ?? ""),
        "scopes": strings.splitTrim((r.headers["x-oauth-scopes"] ?? ""), ","),
        "sso": (r.headers["x-github-sso"] ?? "")
      }
    } : r.status in [401, 403] ? {
      "result": "invalid",
      "reason": "Unauthorized"
    } : validate.unknown(r))`

// Profile attributes describe the owner, not the token's effective permissions.
// Preserve an absent site_admin as nil so it is omitted from reports.
const githubTokenAnalyzeExpr = `let input = validation.analysis;
let scopes = input["scopes"] ?? [];
{
  "reason": len(scopes) == 0 ? "GitHub did not return classic OAuth scope metadata" : "",
  "metadata": {
    "scopes": scopes,
    "sso": input["sso"] ?? "",
    "url": input["url"] ?? "",
    "account_type": input["account_type"] ?? "",
    "site_admin": input["site_admin"],
    "company": input["company"] ?? "",
    "location": input["location"] ?? "",
    "ldap_dn": input["ldap_dn"] ?? "",
    "expires_at": input["expires_at"] ?? ""
  },
  "identity": {
    "id": input["id"] ?? "",
    "username": input["username"] ?? "",
    "name": input["name"] ?? "",
    "email": input["email"] ?? ""
  },
  "capabilities": analysis.capabilities({
    "read": matchesAny(scopes, [
      "^read:",
      "^(?:gist|notifications|project|public_repo|repo(?::status)?|repo_deployment|security_events|user(?::email)?)$"
    ]),
    "write": matchesAny(scopes, [
      "^write:",
      "^delete:packages$",
      "^(?:gist|notifications|project|public_repo|repo(?::status)?|repo_deployment|workflow)$"
    ]),
    "create_credentials": matchesAny(scopes, ["^admin:(?:gpg_key|public_key|ssh_signing_key)$"])
  })
}`

var githubPathFilter = "matchesAny(attributes[\"path\"], [`(?:^|/)@octokit/auth-token/README\\.md$`])"

// This endpoint rejects authenticated requests. A 202 acknowledges submission,
// but does not confirm completed revocation for an individual token.
// https://docs.github.com/en/rest/credentials/revoke
const githubRevokeExpr = `let base_url = env.getOrDefault("GITHUB_BASE_URL", "https://api.github.com");
let r = http.post(base_url + "/credentials/revoke", {
  "Accept": "application/vnd.github+json",
  "Content-Type": "application/json",
  "X-GitHub-Api-Version": "2026-03-10"
}, toJSON({"credentials": [finding["secret"]]}));
r.status == 202 ? {
  "result": "unknown",
  "reason": "GitHub accepted the revocation request; completion is unconfirmed",
  "metadata": {"submitted": true}
} : revoke.unknown(r)`

var _ = Add(config.Rule{
	ID:           "github-pat",
	Confidence:   "high",
	Description:  "Uncovered a GitHub Personal Access Token, potentially leading to unauthorized repository access and sensitive content exposure.",
	Regex:        `ghp_[0-9a-zA-Z]{36}`,
	Keywords:     []string{"ghp_"},
	ValidateExpr: githubTokenExpr,
	AnalyzeExpr:  githubTokenAnalyzeExpr,
	RevokeExpr:   githubRevokeExpr,
	FilterExpr: `entropy(finding["secret"]) <= 3.0
|| ` + githubPathFilter,
	Tests: []config.RuleTest{
		Match("github assignment", `githubToken = "ghp_5fbbd6p84oe7ut4qrttebiwar77s63donnl8"`, "ghp_5fbbd6p84oe7ut4qrttebiwar77s63donnl8"),
		NoMatch("false positive 1", "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
	},
})

var _ = Add(config.Rule{
	ID:           "github-fine-grained-pat",
	Confidence:   "high",
	Description:  "Found a GitHub Fine-Grained Personal Access Token, risking unauthorized repository access and code manipulation.",
	Regex:        `github_pat_\w{82}`,
	Keywords:     []string{"github_pat_"},
	ValidateExpr: githubTokenExpr,
	AnalyzeExpr:  githubTokenAnalyzeExpr,
	RevokeExpr:   githubRevokeExpr,
	FilterExpr:   `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		Match("github assignment", `githubToken = "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"`, "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"),
		NoMatch("false positive 1", "github_pat_xxxxxxxxxxxxxxxxxxxxxx_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
	},
})

var _ = Add(config.Rule{
	ID:           "github-oauth",
	Confidence:   "high",
	Description:  "Discovered a GitHub OAuth Access Token, posing a risk of compromised GitHub account integrations and data leaks.",
	Regex:        `gho_[0-9a-zA-Z]{36}`,
	Keywords:     []string{"gho_"},
	ValidateExpr: githubTokenExpr,
	AnalyzeExpr:  githubTokenAnalyzeExpr,
	RevokeExpr:   githubRevokeExpr,
	FilterExpr:   `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		Match("github assignment", `githubToken = "gho_5fbbd6p84oe7ut4qrttebiwar77s63donnl8"`, "gho_5fbbd6p84oe7ut4qrttebiwar77s63donnl8"),
		NoMatch("false positive 1", "gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
	},
})

// TODO add permissions once the config schema has a stable place for them.
const githubAppTokenExpr = `let base_url = env.getOrDefault("GITHUB_BASE_URL", "https://api.github.com"); (let r = http.get(base_url + "/app", {
      "Accept": "application/vnd.github+json",
      "Authorization": "Bearer " + finding["secret"]
    }); r.status == 200 && (r.json?.slug ?? "") != "" ? {
      "result": "valid",
      "metadata": {"slug": (r.json?.slug ?? ""), "name": (r.json?.name ?? ""), "html_url": (r.json?.html_url ?? ""), "external_url": (r.json?.external_url ?? "")}
    } : r.status in [401, 403] ? {
      "result": "invalid",
      "reason": "Unauthorized"
    } : validate.unknown(r))`

var _ = Add(config.Rule{
	ID:           "github-app-token",
	Confidence:   "high",
	Description:  "Identified a GitHub App Token, which may compromise GitHub application integrations and source code security.",
	Regex:        `(?:ghu|ghs)_[0-9a-zA-Z]{36}`,
	Keywords:     []string{"ghu_", "ghs_"},
	ValidateExpr: githubAppTokenExpr,
	FilterExpr: `entropy(finding["secret"]) <= 3.0
|| ` + githubPathFilter,
	Tests: []config.RuleTest{
		Match("github assignment", `githubToken = "ghs_5fbbd6p84oe7ut4qrttebiwar77s63donnl8"`, "ghs_5fbbd6p84oe7ut4qrttebiwar77s63donnl8"),
		Match("github assignment 2", `githubToken = "ghu_5fbbd6p84oe7ut4qrttebiwar77s63donnl8"`, "ghu_5fbbd6p84oe7ut4qrttebiwar77s63donnl8"),
		NoMatch("false positive 1", "ghu_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
		NoMatch("false positive 2", "ghs_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
	},
})

var _ = Add(config.Rule{
	ID:           "github-refresh-token",
	Confidence:   "high",
	Description:  "Detected a GitHub Refresh Token, which could allow prolonged unauthorized access to GitHub services.",
	Regex:        `ghr_[0-9a-zA-Z]{36}`,
	Keywords:     []string{"ghr_"},
	ValidateExpr: githubTokenExpr,
	RevokeExpr:   githubRevokeExpr,
	FilterExpr:   `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		Match("github assignment", `githubToken = "ghr_5fbbd6p84oe7ut4qrttebiwar77s63donnl8"`, "ghr_5fbbd6p84oe7ut4qrttebiwar77s63donnl8"),
		NoMatch("false positive 1", "ghr_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
	},
})
