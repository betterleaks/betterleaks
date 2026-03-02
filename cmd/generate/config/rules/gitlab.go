package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

// overview with all GitLab tokens:
// https://docs.gitlab.com/ee/security/tokens/index.html#token-prefixes

// gitlabPatValidation validates PATs via the self-inspection endpoint.
// Works for glpat- tokens (both classic and routable formats).
func gitlabPatValidation() *config.Validation {
	return &config.Validation{
		Type:   config.ValidationTypeHTTP,
		Method: "GET",
		URL:    "https://gitlab.com/api/v4/personal_access_tokens/self",
		Headers: map[string]string{
			"PRIVATE-TOKEN": "{{ secret }}",
		},
		Extract: map[string]string{
			"scopes": "json:scopes",
			"name":   "json:name",
		},
		Match: []config.MatchClause{
			{StatusCodes: []int{200}, JSON: map[string]any{"id": "!empty"}, Result: "valid"},
			{StatusCodes: []int{401, 403}, Result: "invalid"},
		},
	}
}

// gitlabTokenValidation validates tokens that support PRIVATE-TOKEN auth
// against the /api/v4/user endpoint. Works for deploy tokens, CI/CD job
// tokens, runner auth tokens, and other prefixed token types.
func gitlabTokenValidation() *config.Validation {
	return &config.Validation{
		Type:   config.ValidationTypeHTTP,
		Method: "GET",
		URL:    "https://gitlab.com/api/v4/user",
		Headers: map[string]string{
			"PRIVATE-TOKEN": "{{ secret }}",
		},
		Match: []config.MatchClause{
			{StatusCodes: []int{200}, JSON: map[string]any{"id": "!empty"}, Result: "valid"},
			{StatusCodes: []int{401, 403}, Result: "invalid"},
		},
	}
}

// gitlabRunnerRegistrationValidation validates runner registration tokens
// via the runners/verify endpoint (form POST).
func gitlabRunnerRegistrationValidation() *config.Validation {
	return &config.Validation{
		Type:   config.ValidationTypeHTTP,
		Method: "POST",
		URL:    "https://gitlab.com/api/v4/runners/verify",
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
		Body: "token={{ secret }}",
		Match: []config.MatchClause{
			{StatusCodes: []int{200}, NegativeWords: []string{"token is missing", "403 Forbidden"}, Result: "valid"},
			{StatusCodes: []int{401, 403}, Result: "invalid"},
		},
	}
}

func GitlabCiCdJobToken() *config.Rule {
	r := config.Rule{
		RuleID:      "gitlab-cicd-job-token",
		Description: "Identified a GitLab CI/CD Job Token, potential access to projects and some APIs on behalf of a user while the CI job is running.",
		Regex:       regexp.MustCompile(`glcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_-]{20}`),
		Entropy:     3,
		Keywords:    []string{"glcbt-"},
		Validation:  gitlabTokenValidation(),
	}
	tps := utils.GenerateSampleSecrets("gitlab", "glcbt-"+secrets.NewSecret(utils.AlphaNumeric("5"))+"_"+secrets.NewSecret(utils.AlphaNumeric("20")))
	return utils.Validate(r, tps, nil)
}

func GitlabDeployToken() *config.Rule {
	r := config.Rule{
		Description: "Identified a GitLab Deploy Token, risking access to repositories, packages and containers with write access.",
		RuleID:      "gitlab-deploy-token",
		Regex:       regexp.MustCompile(`gldt-[0-9a-zA-Z_\-]{20}`),
		Entropy:     3,
		Keywords:    []string{"gldt-"},
		Validation:  gitlabTokenValidation(),
	}
	tps := []string{
		utils.GenerateSampleSecret("gitlab", "gldt-"+secrets.NewSecret(utils.AlphaNumeric("20"))),
	}
	return utils.Validate(r, tps, nil)
}

func GitlabFeatureFlagClientToken() *config.Rule {
	r := config.Rule{
		RuleID:      "gitlab-feature-flag-client-token",
		Description: "Identified a GitLab feature flag client token, risks exposing user lists and features flags used by an application.",
		Regex:       regexp.MustCompile(`glffct-[0-9a-zA-Z_\-]{20}`),
		Entropy:     3,
		Keywords:    []string{"glffct-"},
	}
	tps := utils.GenerateSampleSecrets("gitlab", "glffct-"+secrets.NewSecret(utils.AlphaNumeric("20")))
	return utils.Validate(r, tps, nil)
}

func GitlabFeedToken() *config.Rule {
	r := config.Rule{
		RuleID:      "gitlab-feed-token",
		Description: "Identified a GitLab feed token, risking exposure of user data.",
		Regex:       regexp.MustCompile(`glft-[0-9a-zA-Z_\-]{20}`),
		Entropy:     3,
		Keywords:    []string{"glft-"},
	}
	tps := utils.GenerateSampleSecrets("gitlab", "glft-"+secrets.NewSecret(utils.AlphaNumeric("20")))
	return utils.Validate(r, tps, nil)
}

func GitlabIncomingMailToken() *config.Rule {
	r := config.Rule{
		RuleID:      "gitlab-incoming-mail-token",
		Description: "Identified a GitLab incoming mail token, risking manipulation of data sent by mail.",
		Regex:       regexp.MustCompile(`glimt-[0-9a-zA-Z_\-]{25}`),
		Entropy:     3,
		Keywords:    []string{"glimt-"},
	}
	tps := utils.GenerateSampleSecrets("gitlab", "glimt-"+secrets.NewSecret(utils.AlphaNumeric("25")))
	return utils.Validate(r, tps, nil)
}

func GitlabKubernetesAgentToken() *config.Rule {
	r := config.Rule{
		RuleID:      "gitlab-kubernetes-agent-token",
		Description: "Identified a GitLab Kubernetes Agent token, risking access to repos and registry of projects connected via agent.",
		Regex:       regexp.MustCompile(`glagent-[0-9a-zA-Z_\-]{50}`),
		Entropy:     3,
		Keywords:    []string{"glagent-"},
	}
	tps := utils.GenerateSampleSecrets("gitlab", "glagent-"+secrets.NewSecret(utils.AlphaNumeric("50")))
	return utils.Validate(r, tps, nil)
}

func GitlabOauthAppSecret() *config.Rule {
	r := config.Rule{
		RuleID:      "gitlab-oauth-app-secret",
		Description: "Identified a GitLab OIDC Application Secret, risking access to apps using GitLab as authentication provider.",
		Regex:       regexp.MustCompile(`gloas-[0-9a-zA-Z_\-]{64}`),
		Entropy:     3,
		Keywords:    []string{"gloas-"},
	}
	tps := utils.GenerateSampleSecrets("gitlab", "gloas-"+secrets.NewSecret(utils.AlphaNumeric("64")))
	return utils.Validate(r, tps, nil)
}

func GitlabPat() *config.Rule {
	r := config.Rule{
		RuleID:      "gitlab-pat",
		Description: "Identified a GitLab Personal Access Token, risking unauthorized access to GitLab repositories and codebase exposure.",
		Regex:       regexp.MustCompile(`glpat-[\w-]{20}`),
		Entropy:     3,
		Keywords:    []string{"glpat-"},
		Validation:  gitlabPatValidation(),
	}

	// validate
	tps := utils.GenerateSampleSecrets("gitlab", "glpat-"+secrets.NewSecret(utils.AlphaNumeric("20")))
	fps := []string{
		"glpat-XXXXXXXXXXX-XXXXXXXX",
	}
	return utils.Validate(r, tps, fps)
}

func GitlabPatRoutable() *config.Rule {
	r := config.Rule{
		RuleID:      "gitlab-pat-routable",
		Description: "Identified a GitLab Personal Access Token (routable), risking unauthorized access to GitLab repositories and codebase exposure.",
		Regex:       regexp.MustCompile(`\bglpat-[0-9a-zA-Z_-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7}\b`),
		Entropy:     4,
		Keywords:    []string{"glpat-"},
		Validation:  gitlabPatValidation(),
	}

	// validate
	tps := utils.GenerateSampleSecrets("gitlab", "glpat-"+secrets.NewSecret(utils.AlphaNumeric("27"))+"."+secrets.NewSecret(utils.AlphaNumeric("2"))+secrets.NewSecret(utils.AlphaNumeric("7")))
	fps := []string{
		"glpat-xxxxxxxx-xxxxxxxxxxxxxxxxxx.xxxxxxxxx",
	}
	return utils.Validate(r, tps, fps)
}

func GitlabPipelineTriggerToken() *config.Rule {
	r := config.Rule{
		RuleID:      "gitlab-ptt",
		Description: "Found a GitLab Pipeline Trigger Token, potentially compromising continuous integration workflows and project security.",
		Regex:       regexp.MustCompile(`glptt-[0-9a-f]{40}`),
		Entropy:     3,
		Keywords:    []string{"glptt-"},
		Validation:  gitlabTokenValidation(),
	}

	// validate
	tps := utils.GenerateSampleSecrets("gitlab", "glptt-"+secrets.NewSecret(utils.Hex("40")))
	fps := []string{
		"glptt-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	}
	return utils.Validate(r, tps, fps)
}

func GitlabRunnerRegistrationToken() *config.Rule {
	r := config.Rule{
		RuleID:      "gitlab-rrt",
		Description: "Discovered a GitLab Runner Registration Token, posing a risk to CI/CD pipeline integrity and unauthorized access.",
		Regex:       regexp.MustCompile(`GR1348941[\w-]{20}`),
		Entropy:     3,
		Keywords:    []string{"GR1348941"},
		Validation:  gitlabRunnerRegistrationValidation(),
	}

	tps := utils.GenerateSampleSecrets("gitlab", "GR1348941"+secrets.NewSecret(utils.AlphaNumeric("20")))
	fps := []string{
		"GR134894112312312312312312312",
		"GR1348941XXXXXXXXXXXXXXXXXXXX",
	}
	return utils.Validate(r, tps, fps)
}

func GitlabRunnerAuthenticationToken() *config.Rule {
	r := config.Rule{
		RuleID:      "gitlab-runner-authentication-token",
		Description: "Discovered a GitLab Runner Authentication Token, posing a risk to CI/CD pipeline integrity and unauthorized access.",
		Regex:       regexp.MustCompile(`glrt-[0-9a-zA-Z_\-]{20}`),
		Entropy:     3,
		Keywords:    []string{"glrt-"},
		Validation:  gitlabTokenValidation(),
	}

	tps := utils.GenerateSampleSecrets("gitlab", "glrt-"+secrets.NewSecret(utils.AlphaNumeric("20")))
	return utils.Validate(r, tps, nil)
}

func GitlabRunnerAuthenticationTokenRoutable() *config.Rule {
	r := config.Rule{
		RuleID:      "gitlab-runner-authentication-token-routable",
		Description: "Discovered a GitLab Runner Authentication Token (Routable), posing a risk to CI/CD pipeline integrity and unauthorized access.",
		Regex:       regexp.MustCompile(`\bglrt-t\d_[0-9a-zA-Z_\-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7}\b`),
		Entropy:     4,
		Keywords:    []string{"glrt-"},
		Validation:  gitlabTokenValidation(),
	}

	tps := utils.GenerateSampleSecrets("gitlab", "glrt-t"+secrets.NewSecret(utils.Numeric("1"))+"_"+secrets.NewSecret(utils.AlphaNumeric("27"))+"."+secrets.NewSecret(utils.AlphaNumeric("2"))+secrets.NewSecret(utils.AlphaNumeric("7")))
	fps := []string{
		"glrt-tx_xxxxxxxxxxxxxxxxxxxxxxxxxxx.xxxxxxxxx",
	}

	return utils.Validate(r, tps, fps)
}

func GitlabScimToken() *config.Rule {
	r := config.Rule{
		RuleID:      "gitlab-scim-token",
		Description: "Discovered a GitLab SCIM Token, posing a risk to unauthorized access for a organization or instance.",
		Regex:       regexp.MustCompile(`glsoat-[0-9a-zA-Z_\-]{20}`),
		Entropy:     3,
		Keywords:    []string{"glsoat-"},
	}

	tps := utils.GenerateSampleSecrets("gitlab", "glsoat-"+secrets.NewSecret(utils.AlphaNumeric("20")))
	return utils.Validate(r, tps, nil)
}

func GitlabSessionCookie() *config.Rule {
	r := config.Rule{
		RuleID:      "gitlab-session-cookie",
		Description: "Discovered a GitLab Session Cookie, posing a risk to unauthorized access to a user account.",
		Regex:       regexp.MustCompile(`_gitlab_session=[0-9a-z]{32}`),
		Entropy:     3,
		Keywords:    []string{"_gitlab_session="},
	}

	// validate
	tps := utils.GenerateSampleSecrets("gitlab", "_gitlab_session="+secrets.NewSecret(utils.AlphaNumeric("32")))
	return utils.Validate(r, tps, nil)
}
