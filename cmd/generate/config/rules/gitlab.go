package rules

import (
	"strconv"
	"strings"

	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/regexp"
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
    "token_id": string(int(r.json?.id ?? 0)),
    "token_name": (r.json?.name ?? ""),
    "user_id": string(int(r.json?.user_id ?? 0)),
    "scopes": (r.json?.scopes ?? []),
    "granular": (r.json?.granular ?? false),
    "granular_scopes": (r.json?.granular_scopes ?? [])
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`

	gitlabPatAnalyzeExpr = `let metadata = validation["metadata"] ?? {};
let scopes = metadata["scopes"] ?? [];
let granular_scopes =
  size(metadata["granular_scopes"] ?? []) > 0 ? metadata["granular_scopes"] :
  !((metadata["granular"] ?? false) || "granular" in scopes) || (metadata["token_id"] ?? "") in ["", "0"] ? [] : (
  let headers = {"PRIVATE-TOKEN": finding["secret"]};
  let base_url = env.getOrDefault("GITLAB_BASE_URL", "https://gitlab.com");
  let token_id = metadata["token_id"];
  let detail = http.get(base_url + "/api/v4/personal_access_tokens/" + token_id, headers);
  let detail_scopes = detail.status == 200 ? (detail.json?.granular_scopes ?? []) : [];
  size(detail_scopes) > 0 ? detail_scopes : (metadata["user_id"] ?? "") in ["", "0"] ? [] : (
    let tokens = http.get(base_url + "/api/v4/personal_access_tokens?user_id=" + metadata["user_id"] + "&per_page=100", headers);
    let matching_token = tokens.status == 200 ? find(tokens.json ?? [], {#.id == int(token_id)}) : nil;
    matching_token?.granular_scopes ?? []
  )
);
let permissions = flatten(map(granular_scopes, {#.permissions ?? []}));
let can_read =
  "api" in scopes ||
  startsWithAny(scopes, ["read_", "write_"]) ||
  startsWithAny(permissions, ["download_", "read_"]);
let can_write =
  "api" in scopes || "manage_runner" in scopes ||
  startsWithAny(scopes, ["write_"]) ||
  startsWithAny(permissions, [
    "add_", "approve_", "archive_", "assign_", "cancel_", "create_",
    "delete_", "disable_", "enable_", "execute_", "import_", "manage_",
    "merge_", "move_", "publish_", "renew_", "restore_", "retry_",
    "revoke_", "rotate_", "run_", "set_", "stop_", "transfer_",
    "trigger_", "unarchive_", "update_", "upload_", "write_"
  ]);
{
  "reason": ((metadata["granular"] ?? false) || "granular" in scopes) && size(granular_scopes) == 0 ? "GitLab did not return fine-grained permission details" : "",
  "identity": {
    "id": metadata["user_id"] ?? ""
  },
  "capabilities": flatten([
    can_read ? ["read"] : [],
    can_write ? ["write"] : [],
    ("create_runner" in scopes || "self_rotate" in scopes) ? ["create_credentials"] : [],
    ("sudo" in scopes || "admin_mode" in scopes) ? ["admin"] : []
  ])
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

func GitlabCiCdJobToken() *config.Rule {
	r := config.Rule{
		RuleID:       "gitlab-cicd-job-token",
		Confidence:   "high",
		Description:  "Identified a GitLab CI/CD Job Token, potential access to projects and some APIs on behalf of a user while the CI job is running.",
		Regex:        regexp.MustCompile(`glcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_-]{20}`),
		Keywords:     []string{"glcbt-"},
		ValidateExpr: gitlabUserExpr,
		Filter:       `entropy(finding["secret"]) <= 3.0`,
	}
	tps := utils.GenerateSampleSecrets("gitlab", "glcbt-"+secrets.NewSecret(utils.AlphaNumeric("5"))+"_"+secrets.NewSecretWithEntropy(utils.AlphaNumeric("20"), 3))
	return utils.Validate(r, tps, nil)
}

func GitlabDeployToken() *config.Rule {
	r := config.Rule{
		Description:  "Identified a GitLab Deploy Token, risking access to repositories, packages and containers with write access.",
		RuleID:       "gitlab-deploy-token",
		Confidence:   "high",
		Regex:        regexp.MustCompile(`gldt-[0-9a-zA-Z_\-]{20}`),
		Keywords:     []string{"gldt-"},
		ValidateExpr: gitlabUserExpr,
		Filter:       `entropy(finding["secret"]) <= 3.0`,
	}
	tps := []string{
		utils.GenerateSampleSecret("gitlab", "gldt-"+secrets.NewSecretWithEntropy(utils.AlphaNumeric("20"), 3)),
	}
	return utils.Validate(r, tps, nil)
}

func GitlabFeatureFlagClientToken() *config.Rule {
	r := config.Rule{
		RuleID:      "gitlab-feature-flag-client-token",
		Confidence:  "high",
		Description: "Identified a GitLab feature flag client token, risks exposing user lists and features flags used by an application.",
		Regex:       regexp.MustCompile(`glffct-[0-9a-zA-Z_\-]{20}`),
		Keywords:    []string{"glffct-"},
		Filter:      `entropy(finding["secret"]) <= 3.0`,
	}
	tps := utils.GenerateSampleSecrets("gitlab", "glffct-"+secrets.NewSecretWithEntropy(utils.AlphaNumeric("20"), 3))
	return utils.Validate(r, tps, nil)
}

func GitlabFeedToken() *config.Rule {
	r := config.Rule{
		RuleID:      "gitlab-feed-token",
		Confidence:  "high",
		Description: "Identified a GitLab feed token, risking exposure of user data.",
		Regex:       regexp.MustCompile(`glft-[0-9a-zA-Z_\-]{20}`),
		Keywords:    []string{"glft-"},
		Filter:      `entropy(finding["secret"]) <= 3.0`,
	}
	tps := utils.GenerateSampleSecrets("gitlab", "glft-"+secrets.NewSecretWithEntropy(utils.AlphaNumeric("20"), 3))
	return utils.Validate(r, tps, nil)
}

func GitlabIncomingMailToken() *config.Rule {
	r := config.Rule{
		RuleID:      "gitlab-incoming-mail-token",
		Confidence:  "high",
		Description: "Identified a GitLab incoming mail token, risking manipulation of data sent by mail.",
		Regex:       regexp.MustCompile(`glimt-[0-9a-zA-Z_\-]{25}`),
		Keywords:    []string{"glimt-"},
		Filter:      `entropy(finding["secret"]) <= 3.0`,
	}
	tps := utils.GenerateSampleSecrets("gitlab", "glimt-"+secrets.NewSecretWithEntropy(utils.AlphaNumeric("25"), 3))
	return utils.Validate(r, tps, nil)
}

// GitlabIncomingMailAddressToken finds incoming-mail tokens embedded in GitLab
// reply-by-email addresses. Prefer gitlab-incoming-mail-token (glimt- prefix)
// when both match; this rule covers legacy tokens and arbitrary prefixes.
func GitlabIncomingMailAddressToken() *config.Rule {
	r := config.Rule{
		RuleID:      "gitlab-incoming-mail-address-token",
		Confidence:  "high",
		Description: "Identified a GitLab incoming mail token embedded in an email address, risking manipulation of data sent by mail.",
		Regex:       regexp.MustCompile(`incoming\+(?:[A-Za-z0-9._-]+-)?\d+-([A-Za-z0-9_-]+)-(?:issue(?:-\d+)?|merge-request)@`),
		Keywords:    []string{"incoming+"},
		Specificity: 50,
		Filter:      `entropy(finding["secret"]) <= 3.0`,
	}
	token := secrets.NewSecretWithEntropy(utils.AlphaNumeric("25"), 3)
	glimtToken := "glimt-" + secrets.NewSecretWithEntropy(utils.AlphaNumeric("25"), 3)
	tps := []string{
		"incoming+gitlab-org-project-123-" + token + "-issue@example.com",
		"incoming+my.group_path-456-" + token + "-merge-request@gitlab.example.com",
		"incoming+project.path-789-" + token + "-issue-42@example.com",
		"incoming+gitlab-org-gitlab-foss-20-" + glimtToken + "-issue@example.com",
	}
	return utils.Validate(r, tps, nil)
}

func GitlabKubernetesAgentToken() *config.Rule {
	r := config.Rule{
		RuleID:      "gitlab-kubernetes-agent-token",
		Confidence:  "high",
		Description: "Identified a GitLab Kubernetes Agent token, risking access to repos and registry of projects connected via agent.",
		Regex:       regexp.MustCompile(`glagent-[0-9a-zA-Z_\-]{50}`),
		Keywords:    []string{"glagent-"},
		Filter:      `entropy(finding["secret"]) <= 3.0`,
	}
	tps := utils.GenerateSampleSecrets("gitlab", "glagent-"+secrets.NewSecretWithEntropy(utils.AlphaNumeric("50"), 3))
	return utils.Validate(r, tps, nil)
}

func GitlabOauthAppSecret() *config.Rule {
	r := config.Rule{
		RuleID:      "gitlab-oauth-app-secret",
		Confidence:  "high",
		Description: "Identified a GitLab OIDC Application Secret, risking access to apps using GitLab as authentication provider.",
		Regex:       regexp.MustCompile(`gloas-[0-9a-zA-Z_\-]{64}`),
		Keywords:    []string{"gloas-"},
		Filter:      `entropy(finding["secret"]) <= 3.0`,
	}
	tps := utils.GenerateSampleSecrets("gitlab", "gloas-"+secrets.NewSecretWithEntropy(utils.AlphaNumeric("64"), 3))
	return utils.Validate(r, tps, nil)
}

func GitlabPat() *config.Rule {
	r := config.Rule{
		RuleID:       "gitlab-pat",
		Confidence:   "high",
		Description:  "Identified a GitLab Personal Access Token, risking unauthorized access to GitLab repositories and codebase exposure.",
		Regex:        regexp.MustCompile(`glpat-[\w-]{20}`),
		Keywords:     []string{"glpat-"},
		ValidateExpr: gitlabPatExpr,
		AnalyzeExpr:  gitlabPatAnalyzeExpr,
		Filter:       `entropy(finding["secret"]) <= 3.0`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("gitlab", "glpat-"+secrets.NewSecretWithEntropy(utils.AlphaNumeric("20"), 3))
	fps := []string{
		"glpat-XXXXXXXXXXX-XXXXXXXX",
	}
	return utils.Validate(r, tps, fps)
}

func GitlabPatRoutable() *config.Rule {
	r := config.Rule{
		RuleID:       "gitlab-pat-routable",
		Confidence:   "high",
		Description:  "Identified a GitLab Personal Access Token (routable), risking unauthorized access to GitLab repositories and codebase exposure.",
		Regex:        regexp.MustCompile(`\bglpat-[0-9a-zA-Z_-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7}\b`),
		Keywords:     []string{"glpat-"},
		ValidateExpr: gitlabPatExpr,
		AnalyzeExpr:  gitlabPatAnalyzeExpr,
		Filter:       `entropy(finding["secret"]) <= 4.0`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("gitlab", "glpat-"+secrets.NewSecretWithEntropy(utils.AlphaNumeric("27"), 4)+"."+secrets.NewSecret(utils.AlphaNumeric("2"))+secrets.NewSecret(utils.AlphaNumeric("7")))
	fps := []string{
		"glpat-xxxxxxxx-xxxxxxxxxxxxxxxxxx.xxxxxxxxx",
	}
	return utils.Validate(r, tps, fps)
}

func GitlabPatRoutableVersioned() *config.Rule {
	r := config.Rule{
		RuleID:       "gitlab-pat-routable-versioned",
		Confidence:   "high",
		Description:  "Identified a GitLab Personal Access Token (routable, versioned), risking unauthorized access to GitLab repositories and codebase exposure.",
		Regex:        regexp.MustCompile(`\bglpat-[0-9a-zA-Z_-]{27,300}\.[0-9a-z]{2}\.[0-9a-z]{9}\b`),
		Keywords:     []string{"glpat-"},
		ValidateExpr: gitlabPatExpr,
		AnalyzeExpr:  gitlabPatAnalyzeExpr,
		Filter:       `entropy(finding["secret"]) <= 4.0`,
	}

	// validate
	payload := secrets.NewSecretWithEntropy(utils.AlphaNumeric("27"), 4)
	payloadLenStr := strconv.FormatInt(int64(len(payload)), 36)
	paddedLen := strings.Repeat("0", 2-len(payloadLenStr)) + payloadLenStr

	tps := utils.GenerateSampleSecrets("gitlab", "glpat-"+payload+"."+paddedLen+"."+secrets.NewSecret(utils.AlphaNumeric("9")))
	fps := []string{
		"glpat-xxxxxxxx-xxxxxxxxxxxxxxxxxx.xx.xxxxxxx",
	}
	return utils.Validate(r, tps, fps)
}

func GitlabPipelineTriggerToken() *config.Rule {
	r := config.Rule{
		RuleID:       "gitlab-ptt",
		Confidence:   "high",
		Description:  "Found a GitLab Pipeline Trigger Token, potentially compromising continuous integration workflows and project security.",
		Regex:        regexp.MustCompile(`glptt-[0-9a-f]{40}`),
		Keywords:     []string{"glptt-"},
		ValidateExpr: gitlabUserExpr,
		Filter:       `entropy(finding["secret"]) <= 3.0`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("gitlab", "glptt-"+secrets.NewSecretWithEntropy(utils.Hex("40"), 3))
	fps := []string{
		"glptt-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	}
	return utils.Validate(r, tps, fps)
}

func GitlabRunnerRegistrationToken() *config.Rule {
	r := config.Rule{
		RuleID:       "gitlab-rrt",
		Confidence:   "high",
		Description:  "Discovered a GitLab Runner Registration Token, posing a risk to CI/CD pipeline integrity and unauthorized access.",
		Regex:        regexp.MustCompile(`GR1348941[\w-]{20}`),
		Keywords:     []string{"GR1348941"},
		ValidateExpr: gitlabRunnerRegistrationExpr,
		Filter:       `entropy(finding["secret"]) <= 3.0`,
	}

	tps := utils.GenerateSampleSecrets("gitlab", "GR1348941"+secrets.NewSecretWithEntropy(utils.AlphaNumeric("20"), 3))
	fps := []string{
		"GR134894112312312312312312312",
		"GR1348941XXXXXXXXXXXXXXXXXXXX",
	}
	return utils.Validate(r, tps, fps)
}

func GitlabRunnerAuthenticationToken() *config.Rule {
	r := config.Rule{
		RuleID:       "gitlab-runner-authentication-token",
		Confidence:   "high",
		Description:  "Discovered a GitLab Runner Authentication Token, posing a risk to CI/CD pipeline integrity and unauthorized access.",
		Regex:        regexp.MustCompile(`glrt-[0-9a-zA-Z_\-]{20}`),
		Keywords:     []string{"glrt-"},
		ValidateExpr: gitlabUserExpr,
		Filter:       `entropy(finding["secret"]) <= 3.0`,
	}

	tps := utils.GenerateSampleSecrets("gitlab", "glrt-"+secrets.NewSecretWithEntropy(utils.AlphaNumeric("20"), 3))
	return utils.Validate(r, tps, nil)
}

func GitlabRunnerAuthenticationTokenRoutable() *config.Rule {
	r := config.Rule{
		RuleID:       "gitlab-runner-authentication-token-routable",
		Confidence:   "high",
		Description:  "Discovered a GitLab Runner Authentication Token (Routable), posing a risk to CI/CD pipeline integrity and unauthorized access.",
		Regex:        regexp.MustCompile(`\bglrt-t\d_[0-9a-zA-Z_\-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7}\b`),
		Keywords:     []string{"glrt-"},
		ValidateExpr: gitlabUserExpr,
		Filter:       `entropy(finding["secret"]) <= 4.0`,
	}

	tps := utils.GenerateSampleSecrets("gitlab", "glrt-t"+secrets.NewSecret(utils.Numeric("1"))+"_"+secrets.NewSecretWithEntropy(utils.AlphaNumeric("27"), 4)+"."+secrets.NewSecret(utils.AlphaNumeric("2"))+secrets.NewSecret(utils.AlphaNumeric("7")))
	fps := []string{
		"glrt-tx_xxxxxxxxxxxxxxxxxxxxxxxxxxx.xxxxxxxxx",
	}

	return utils.Validate(r, tps, fps)
}

func GitlabScimToken() *config.Rule {
	r := config.Rule{
		RuleID:      "gitlab-scim-token",
		Confidence:  "high",
		Description: "Discovered a GitLab SCIM Token, posing a risk to unauthorized access for a organization or instance.",
		Regex:       regexp.MustCompile(`glsoat-[0-9a-zA-Z_\-]{20}`),
		Keywords:    []string{"glsoat-"},
		Filter:      `entropy(finding["secret"]) <= 3.0`,
	}

	tps := utils.GenerateSampleSecrets("gitlab", "glsoat-"+secrets.NewSecretWithEntropy(utils.AlphaNumeric("20"), 3))
	return utils.Validate(r, tps, nil)
}

func GitlabSessionCookie() *config.Rule {
	r := config.Rule{
		RuleID:      "gitlab-session-cookie",
		Confidence:  "high",
		Description: "Discovered a GitLab Session Cookie, posing a risk to unauthorized access to a user account.",
		Regex:       regexp.MustCompile(`_gitlab_session=[0-9a-z]{32}`),
		Keywords:    []string{"_gitlab_session="},
		Filter:      `entropy(finding["secret"]) <= 3.0`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("gitlab", "_gitlab_session="+secrets.NewSecretWithEntropy(utils.AlphaNumeric("32"), 3))
	return utils.Validate(r, tps, nil)
}
