package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

const githubTokenCEL = `cel.bind(r,
  http.get("https://api.github.com/user", {
    "Accept": "application/vnd.github+json",
    "Authorization": "token " + secret
  }),
  r.status == 200 && r.json.?login.orValue("") != "" ? {
    "result": "valid",
    "username": r.json.?login.orValue(""),
    "name": r.json.?name.orValue(""),
    "scopes": r.headers[?"x-oauth-scopes"].orValue("")
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`

var githubAllowlist = []*config.Allowlist{
	{
		Paths: []*regexp.Regexp{
			// https://github.com/octokit/auth-token.js/?tab=readme-ov-file#createtokenauthtoken-options
			regexp.MustCompile(`(?:^|/)@octokit/auth-token/README\.md$`),
		},
	},
}

func GitHubPat() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "github-pat",
		Description: "Uncovered a GitHub Personal Access Token, potentially leading to unauthorized repository access and sensitive content exposure.",
		Regex:       regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`),
		Entropy:     3,
		Keywords:    []string{"ghp_"},
		Allowlists:  githubAllowlist,
		ValidateCEL: githubTokenCEL,
	}

	// validate
	tps := utils.GenerateSampleSecrets("github", "ghp_"+secrets.NewSecretWithEntropy(utils.AlphaNumeric("36"), 3))
	fps := []string{
		"ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	}
	return utils.Validate(r, tps, fps)
}

func GitHubFineGrainedPat() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "github-fine-grained-pat",
		Description: "Found a GitHub Fine-Grained Personal Access Token, risking unauthorized repository access and code manipulation.",
		Regex:       regexp.MustCompile(`github_pat_\w{82}`),
		Entropy:     3,
		Keywords:    []string{"github_pat_"},
		ValidateCEL: githubTokenCEL,
	}

	// validate
	tps := utils.GenerateSampleSecrets("github", "github_pat_"+secrets.NewSecretWithEntropy(utils.AlphaNumeric("82"), 3))
	fps := []string{
		"github_pat_xxxxxxxxxxxxxxxxxxxxxx_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	}
	return utils.Validate(r, tps, fps)
}

func GitHubOauth() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "github-oauth",
		Description: "Discovered a GitHub OAuth Access Token, posing a risk of compromised GitHub account integrations and data leaks.",
		Regex:       regexp.MustCompile(`gho_[0-9a-zA-Z]{36}`),
		Entropy:     3,
		Keywords:    []string{"gho_"},
		ValidateCEL: githubTokenCEL,
	}

	// validate
	tps := utils.GenerateSampleSecrets("github", "gho_"+secrets.NewSecretWithEntropy(utils.AlphaNumeric("36"), 3))
	fps := []string{
		"gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	}
	return utils.Validate(r, tps, fps)
}

// TODO add this later once we confirm orValue({}) is working
// "permissions": r.json.?permissions.orValue({})
const githubAppTokenCEL = `cel.bind(r,
  http.get("https://api.github.com/app", {
    "Accept": "application/vnd.github+json",
    "Authorization": "Bearer " + secret
  }),
  r.status == 200 && r.json.?slug.orValue("") != "" ? {
    "result": "valid",
    "slug": r.json.?slug.orValue(""),
    "name": r.json.?name.orValue(""),
    "html_url": r.json.?html_url.orValue(""),
	"external_url": r.json.?external_url.orValue("")
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`

func GitHubApp() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "github-app-token",
		Description: "Identified a GitHub App Token, which may compromise GitHub application integrations and source code security.",
		Regex:       regexp.MustCompile(`(?:ghu|ghs)_[0-9a-zA-Z]{36}`),
		Entropy:     3,
		Keywords:    []string{"ghu_", "ghs_"},
		Allowlists:  githubAllowlist,
		ValidateCEL: githubAppTokenCEL,
	}

	// validate
	tps := utils.GenerateSampleSecrets("github", "ghs_"+secrets.NewSecretWithEntropy(utils.AlphaNumeric("36"), 3))
	tps = append(tps, utils.GenerateSampleSecrets("github", "ghu_"+secrets.NewSecretWithEntropy(utils.AlphaNumeric("36"), 3))...)
	fps := []string{
		"ghu_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"ghs_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	}
	return utils.Validate(r, tps, fps)
}

func GitHubRefresh() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "github-refresh-token",
		Description: "Detected a GitHub Refresh Token, which could allow prolonged unauthorized access to GitHub services.",
		Regex:       regexp.MustCompile(`ghr_[0-9a-zA-Z]{36}`),
		Entropy:     3,
		Keywords:    []string{"ghr_"},
		ValidateCEL: githubTokenCEL,
	}

	// validate
	tps := utils.GenerateSampleSecrets("github", "ghr_"+secrets.NewSecretWithEntropy(utils.AlphaNumeric("36"), 3))
	fps := []string{
		"ghr_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	}
	return utils.Validate(r, tps, fps)
}
