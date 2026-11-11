package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
)

// overview with all GitLab tokens:
// https://docs.gitlab.com/ee/security/tokens/index.html#token-prefixes

const (
	// gitlabUserExpr validates tokens against the /api/v4/user endpoint.
	// Works for deploy tokens, CI/CD job tokens, runner auth tokens, etc.
	gitlabUserExpr = `let r = http.get("https://gitlab.com/api/v4/user", {
    "PRIVATE-TOKEN": finding["secret"]
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`

	// gitlabPatExpr validates PATs via the self-inspection endpoint (glpat- tokens).
	gitlabPatExpr = `let base_url = env.getOrDefault("GITLAB_BASE_URL", "https://gitlab.com");
  let r = http.get(base_url + "/api/v4/personal_access_tokens/self", {
    "PRIVATE-TOKEN": finding["secret"]
  }); r.status == 200 ? {
    "result": "valid",
    "analysis": {
      "token_id": string(int(r.json?.id ?? 0)),
      "token_name": (r.json?.name ?? ""),
      "user_id": string(int(r.json?.user_id ?? 0)),
      "scopes": (r.json?.granular ?? false) ? nil : (r.json?.scopes ?? []),
      "granular": (r.json?.granular ?? false)
    }
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`

	gitlabPatAnalyzeExpr = `let input = validation.analysis;
let scopes = input["scopes"] ?? [];
let granular = input["granular"] ?? false;
let granular_scopes =
  len(input["granular_scopes"] ?? []) > 0 ? input["granular_scopes"] :
  !granular || (input["token_id"] ?? "") in ["", "0"] || (input["user_id"] ?? "") in ["", "0"] ? [] : (
  let headers = {"PRIVATE-TOKEN": finding["secret"]};
  let base_url = env.getOrDefault("GITLAB_BASE_URL", "https://gitlab.com");
  let token_id = input["token_id"];
  let tokens = http.get(base_url + "/api/v4/personal_access_tokens?user_id=" + input["user_id"] + "&state=active&per_page=100", headers);
  let matching_token = tokens.status == 200 ? find(tokens.json ?? [], {#.id == int(token_id)}) : nil;
  matching_token?.granular_scopes ?? []
);
let granular_permissions = flatten(map(granular_scopes, {#.permissions ?? []}));
let grants = flatten([
  granular ? [] : scopes,
  granular_permissions
]);
let can_read = matchesAny(grants, ["^(?:api$|download_|read_|write_)"]);
let can_write = matchesAny(grants, ["^(?:api$|manage_runner$|add_|approve_|archive_|assign_|cancel_|create_|delete_|disable_|enable_|execute_|import_|manage_|merge_|move_|publish_|renew_|restore_|retry_|revoke_|rotate_|run_|set_|stop_|transfer_|trigger_|unarchive_|update_|upload_|write_)"]);
let can_create_credentials = intersects(grants, ["create_runner", "self_rotate"]);
let can_admin = intersects(grants, ["sudo", "admin_mode"]);
{
  "reason": granular && len(granular_permissions) == 0 ? "GitLab did not return fine-grained permission details" :
    len(grants) > 0 && !can_read && !can_write && !can_create_credentials && !can_admin ? "GitLab returned no recognized permission grants" : "",
  "metadata": len(grants) > 0 ? {
    "permissions": grants
  } : {},
  "identity": {
    "id": input["user_id"] ?? ""
  },
  "capabilities": analysis.capabilities({
    "read": can_read,
    "write": can_write,
    "create_credentials": can_create_credentials,
    "admin": can_admin
  })
}`

	// gitlabRunnerRegistrationExpr validates runner registration tokens via POST.
	gitlabRunnerRegistrationExpr = `let r = http.post("https://gitlab.com/api/v4/runners/verify", {
    "Content-Type": "application/x-www-form-urlencoded"
  }, "token=" + finding["secret"]); r.status == 200 && !(r.body contains "token is missing") && !(r.body contains "403 Forbidden") ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`
)

var _ = Add(config.Rule{
	ID:           "gitlab-cicd-job-token",
	Confidence:   "high",
	Description:  "Identified a GitLab CI/CD Job Token, potential access to projects and some APIs on behalf of a user while the CI job is running.",
	Regex:        `glcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_-]{20}`,
	Keywords:     []string{"glcbt-"},
	ValidateExpr: gitlabUserExpr,
	FilterExpr:   `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		Match("gitlab assignment", `gitlabToken = "glcbt-5fbbd_5fbbd6p84oe7ut4qrtte"`, "glcbt-5fbbd_5fbbd6p84oe7ut4qrtte"),
	},
})

var _ = Add(config.Rule{
	Description:  "Identified a GitLab Deploy Token, risking access to repositories, packages and containers with write access.",
	ID:           "gitlab-deploy-token",
	Confidence:   "high",
	Regex:        `gldt-[0-9a-zA-Z_\-]{20}`,
	Keywords:     []string{"gldt-"},
	ValidateExpr: gitlabUserExpr,
	FilterExpr:   `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		Match("true positive 1", `gitlab_api_token = "gldt-5fbbd6p84oe7ut4qrtte"`, "gldt-5fbbd6p84oe7ut4qrtte"),
	},
})

var _ = Add(config.Rule{
	ID:          "gitlab-feature-flag-client-token",
	Confidence:  "high",
	Description: "Identified a GitLab feature flag client token, risks exposing user lists and features flags used by an application.",
	Regex:       `glffct-[0-9a-zA-Z_\-]{20}`,
	Keywords:    []string{"glffct-"},
	FilterExpr:  `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		Match("gitlab assignment", `gitlabToken = "glffct-5fbbd6p84oe7ut4qrtte"`, "glffct-5fbbd6p84oe7ut4qrtte"),
	},
})

var _ = Add(config.Rule{
	ID:          "gitlab-feed-token",
	Confidence:  "high",
	Description: "Identified a GitLab feed token, risking exposure of user data.",
	Regex:       `glft-[0-9a-zA-Z_\-]{20}`,
	Keywords:    []string{"glft-"},
	FilterExpr:  `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		Match("gitlab assignment", `gitlabToken = "glft-5fbbd6p84oe7ut4qrtte"`, "glft-5fbbd6p84oe7ut4qrtte"),
	},
})

var _ = Add(config.Rule{
	ID:          "gitlab-incoming-mail-token",
	Confidence:  "high",
	Description: "Identified a GitLab incoming mail token, risking manipulation of data sent by mail.",
	Regex:       `glimt-[0-9a-zA-Z_\-]{25}`,
	Keywords:    []string{"glimt-"},
	FilterExpr:  `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		Match("gitlab assignment", `gitlabToken = "glimt-5fbbd6p84oe7ut4qrttebiwar"`, "glimt-5fbbd6p84oe7ut4qrttebiwar"),
	},
})

// GitlabIncomingMailAddressToken finds incoming-mail tokens embedded in GitLab
// reply-by-email addresses. Prefer gitlab-incoming-mail-token (glimt- prefix)
// when both match; this rule covers legacy tokens and arbitrary prefixes.
var _ = Add(config.Rule{
	ID:          "gitlab-incoming-mail-address-token",
	Confidence:  "high",
	Description: "Identified a GitLab incoming mail token embedded in an email address, risking manipulation of data sent by mail.",
	Regex:       `incoming\+(?:[A-Za-z0-9._-]+-)?\d+-([A-Za-z0-9_-]+)-(?:issue(?:-\d+)?|merge-request)@`,
	Keywords:    []string{"incoming+"},
	Specificity: -50,
	FilterExpr:  `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		Match("true positive 1", "incoming+gitlab-org-project-123-5fbbd6p84oe7ut4qrttebiwar-issue@example.com", "5fbbd6p84oe7ut4qrttebiwar"),
		Match("true positive 2", "incoming+my.group_path-456-5fbbd6p84oe7ut4qrttebiwar-merge-request@gitlab.example.com", "5fbbd6p84oe7ut4qrttebiwar"),
		Match("true positive 3", "incoming+project.path-789-5fbbd6p84oe7ut4qrttebiwar-issue-42@example.com", "5fbbd6p84oe7ut4qrttebiwar"),
		Match("true positive 4", "incoming+gitlab-org-gitlab-foss-20-glimt-5fbbd6p84oe7ut4qrttebiwar-issue@example.com", "glimt-5fbbd6p84oe7ut4qrttebiwar"),
	},
})

var _ = Add(config.Rule{
	ID:          "gitlab-kubernetes-agent-token",
	Confidence:  "high",
	Description: "Identified a GitLab Kubernetes Agent token, risking access to repos and registry of projects connected via agent.",
	Regex:       `glagent-[0-9a-zA-Z_\-]{50}`,
	Keywords:    []string{"glagent-"},
	FilterExpr:  `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		Match("gitlab assignment", `gitlabToken = "glagent-5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl"`, "glagent-5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl"),
	},
})

var _ = Add(config.Rule{
	ID:          "gitlab-oauth-app-secret",
	Confidence:  "high",
	Description: "Identified a GitLab OIDC Application Secret, risking access to apps using GitLab as authentication provider.",
	Regex:       `gloas-[0-9a-zA-Z_\-]{64}`,
	Keywords:    []string{"gloas-"},
	FilterExpr:  `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		Match("gitlab assignment", `gitlabToken = "gloas-5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7nz6lc"`, "gloas-5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7nz6lc"),
	},
})

// https://docs.gitlab.com/api/personal_access_tokens/#self-revoke
const gitlabPatRevokeExpr = `let base_url = env.getOrDefault("GITLAB_BASE_URL", "https://gitlab.com");
let r = http.delete(base_url + "/api/v4/personal_access_tokens/self", {
  "PRIVATE-TOKEN": finding["secret"]
}); r.status == 204 ? {
  "result": "revoked"
} : revoke.unknown(r)`

var _ = Add(config.Rule{
	ID:           "gitlab-pat",
	Confidence:   "high",
	Description:  "Identified a GitLab Personal Access Token, risking unauthorized access to GitLab repositories and codebase exposure.",
	Regex:        `glpat-[\w-]{20}`,
	Keywords:     []string{"glpat-"},
	ValidateExpr: gitlabPatExpr,
	AnalyzeExpr:  gitlabPatAnalyzeExpr,
	RevokeExpr:   gitlabPatRevokeExpr,
	FilterExpr:   `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		Match("gitlab assignment", `gitlabToken = "glpat-5fbbd6p84oe7ut4qrtte"`, "glpat-5fbbd6p84oe7ut4qrtte"),
		NoMatch("false positive 1", "glpat-XXXXXXXXXXX-XXXXXXXX"),
	},
})

var _ = Add(config.Rule{
	ID:           "gitlab-pat-routable",
	Confidence:   "high",
	Description:  "Identified a GitLab Personal Access Token (routable), risking unauthorized access to GitLab repositories and codebase exposure.",
	Regex:        `\bglpat-[0-9a-zA-Z_-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7}\b`,
	Keywords:     []string{"glpat-"},
	ValidateExpr: gitlabPatExpr,
	AnalyzeExpr:  gitlabPatAnalyzeExpr,
	RevokeExpr:   gitlabPatRevokeExpr,
	FilterExpr:   `entropy(finding["secret"]) <= 4.0`,
	Tests: []config.RuleTest{
		Match("gitlab assignment", `gitlabToken = "glpat-5fbbd6p84oe7ut4qrttebiwar77.5f5fbbd6p"`, "glpat-5fbbd6p84oe7ut4qrttebiwar77.5f5fbbd6p"),
		NoMatch("false positive 1", "glpat-xxxxxxxx-xxxxxxxxxxxxxxxxxx.xxxxxxxxx"),
	},
})

var _ = Add(config.Rule{
	ID:           "gitlab-pat-routable-versioned",
	Confidence:   "high",
	Description:  "Identified a GitLab Personal Access Token (routable, versioned), risking unauthorized access to GitLab repositories and codebase exposure.",
	Regex:        `\bglpat-[0-9a-zA-Z_-]{27,300}\.[0-9a-z]{2}\.[0-9a-z]{9}\b`,
	Keywords:     []string{"glpat-"},
	ValidateExpr: gitlabPatExpr,
	AnalyzeExpr:  gitlabPatAnalyzeExpr,
	RevokeExpr:   gitlabPatRevokeExpr,
	FilterExpr:   `entropy(finding["secret"]) <= 4.0`,
	Tests: []config.RuleTest{
		Match("gitlab assignment", `gitlabToken = "glpat-5fbbd6p84oe7ut4qrttebiwar77.0r.5fbbd6p84"`, "glpat-5fbbd6p84oe7ut4qrttebiwar77.0r.5fbbd6p84"),
		NoMatch("false positive 1", "glpat-xxxxxxxx-xxxxxxxxxxxxxxxxxx.xx.xxxxxxx"),
	},
})

var _ = Add(config.Rule{
	ID:           "gitlab-ptt",
	Confidence:   "high",
	Description:  "Found a GitLab Pipeline Trigger Token, potentially compromising continuous integration workflows and project security.",
	Regex:        `glptt-[0-9a-f]{40}`,
	Keywords:     []string{"glptt-"},
	ValidateExpr: gitlabUserExpr,
	FilterExpr:   `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		Match("gitlab assignment", `gitlabToken = "glptt-1f7b169c846f218ab552fa82fbf86758bf5c97d2"`, "glptt-1f7b169c846f218ab552fa82fbf86758bf5c97d2"),
		NoMatch("false positive 1", "glptt-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
	},
})

var _ = Add(config.Rule{
	ID:           "gitlab-rrt",
	Confidence:   "high",
	Description:  "Discovered a GitLab Runner Registration Token, posing a risk to CI/CD pipeline integrity and unauthorized access.",
	Regex:        `GR1348941[\w-]{20}`,
	Keywords:     []string{"GR1348941"},
	ValidateExpr: gitlabRunnerRegistrationExpr,
	FilterExpr:   `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		Match("gitlab assignment", `gitlabToken = "GR13489415fbbd6p84oe7ut4qrtte"`, "GR13489415fbbd6p84oe7ut4qrtte"),
		NoMatch("false positive 1", "GR134894112312312312312312312"),
		NoMatch("false positive 2", "GR1348941XXXXXXXXXXXXXXXXXXXX"),
	},
})

var _ = Add(config.Rule{
	ID:           "gitlab-runner-authentication-token",
	Confidence:   "high",
	Description:  "Discovered a GitLab Runner Authentication Token, posing a risk to CI/CD pipeline integrity and unauthorized access.",
	Regex:        `glrt-[0-9a-zA-Z_\-]{20}`,
	Keywords:     []string{"glrt-"},
	ValidateExpr: gitlabUserExpr,
	FilterExpr:   `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		Match("gitlab assignment", `gitlabToken = "glrt-5fbbd6p84oe7ut4qrtte"`, "glrt-5fbbd6p84oe7ut4qrtte"),
	},
})

var _ = Add(config.Rule{
	ID:           "gitlab-runner-authentication-token-routable",
	Confidence:   "high",
	Description:  "Discovered a GitLab Runner Authentication Token (Routable), posing a risk to CI/CD pipeline integrity and unauthorized access.",
	Regex:        `\bglrt-t\d_[0-9a-zA-Z_\-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7}\b`,
	Keywords:     []string{"glrt-"},
	ValidateExpr: gitlabUserExpr,
	FilterExpr:   `entropy(finding["secret"]) <= 4.0`,
	Tests: []config.RuleTest{
		Match("gitlab assignment", `gitlabToken = "glrt-t1_5fbbd6p84oe7ut4qrttebiwar77.5f5fbbd6p"`, "glrt-t1_5fbbd6p84oe7ut4qrttebiwar77.5f5fbbd6p"),
		NoMatch("false positive 1", "glrt-tx_xxxxxxxxxxxxxxxxxxxxxxxxxxx.xxxxxxxxx"),
	},
})

var _ = Add(config.Rule{
	ID:          "gitlab-scim-token",
	Confidence:  "high",
	Description: "Discovered a GitLab SCIM Token, posing a risk to unauthorized access for a organization or instance.",
	Regex:       `glsoat-[0-9a-zA-Z_\-]{20}`,
	Keywords:    []string{"glsoat-"},
	FilterExpr:  `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		Match("gitlab assignment", `gitlabToken = "glsoat-5fbbd6p84oe7ut4qrtte"`, "glsoat-5fbbd6p84oe7ut4qrtte"),
	},
})

var _ = Add(config.Rule{
	ID:          "gitlab-session-cookie",
	Confidence:  "high",
	Description: "Discovered a GitLab Session Cookie, posing a risk to unauthorized access to a user account.",
	Regex:       `_gitlab_session=[0-9a-z]{32}`,
	Keywords:    []string{"_gitlab_session="},
	FilterExpr:  `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		Match("gitlab assignment", `gitlabToken = "_gitlab_session=5fbbd6p84oe7ut4qrttebiwar77s63do"`, "_gitlab_session=5fbbd6p84oe7ut4qrttebiwar77s63do"),
	},
})
