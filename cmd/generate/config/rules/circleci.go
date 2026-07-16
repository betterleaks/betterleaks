package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func CircleCIPersonalToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "circleci-personal-token",
		Description: "CircleCI personal access token.",
		Regex:       regexp.MustCompile(`\b(CCIPAT_[a-zA-Z0-9]{22}_[a-z0-9]{40})`),
		Keywords:    []string{"CCIPAT_"},
		ValidateExpr: `let r = http.get("https://circleci.com/api/v2/me", {
    "Accept": "application/json",
    "Circle-Token": finding["secret"]
  }); r.status == 200 && (r.json?.id ?? "") != "" ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	}

	// validate
	tps := []string{
		`CCIPAT_FERZRjTN451xnDCy1y9gWn_79fb6ca4d0e5f833612eee17de397a9dca0a9e9f`,
	}
	fps := []string{
		`CCIPAT_short`,
	}
	return utils.Validate(r, tps, fps)
}

func CircleCIProjectToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "circleci-project-token",
		Description: "CircleCI project token.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"circleci"}, `[a-f0-9]{40}`, true),
		Keywords:    []string{"circleci"},
		ValidateExpr: `let r = http.get("https://circleci.com/api/v1.1/projects", {
    "Circle-Token": finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.3),
	}

	// validate
	tps := []string{
		`circleci_project_secret = 'ca61263bf9a4dceecd00edaaacb4eaee74e8682f'`,
	}
	fps := []string{
		`other_project = 'ca61263bf9a4dceecd00edaaacb4eaee74e8682f'`,
	}
	return utils.Validate(r, tps, fps)
}
