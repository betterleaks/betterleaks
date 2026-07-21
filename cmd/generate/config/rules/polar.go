package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

const polarUserTokenValidateExpr = `let r = http.get("https://api.polar.sh/v1/oauth2/userinfo", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 && r.json?.sub != null ? {
    "result": "valid"
  } : r.status == 403 ? {
    "result": "valid",
    "reason": "Authenticated but user-info access is restricted"
  } : r.status == 401 && (r.json?.error ?? "") == "invalid_token" ? {
    "result": "invalid",
    "reason": "Invalid token"
  } : validate.unknown(r)`

func PolarOrganizationAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "polar-organization-access-token",
		Description: "Polar organization access token.",
		Regex:       utils.GenerateUniqueTokenRegex(`polar_oat_[A-Za-z0-9_-]{20,100}`, false),
		Keywords:    []string{"polar_oat_"},
		ValidateExpr: `let r = http.get("https://api.polar.sh/v1/organizations/", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 && r.json?.items != null ? {
    "result": "valid"
  } : r.status == 403 ? {
    "result": "valid",
    "reason": "Authenticated but organization access is restricted"
  } : r.status == 401 && (r.json?.error ?? "") == "invalid_token" ? {
    "result": "invalid",
    "reason": "Invalid token"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.5),
	}

	// validate
	tps := []string{
		"POLAR_ACCESS_TOKEN=polar_oat_" + secrets.NewSecretWithEntropy(`[A-Za-z0-9_-]{40}`, 3.5),
	}
	fps := polarTokenFalsePositives("polar_oat_")
	return utils.Validate(r, tps, fps)
}

func PolarPersonalAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:       "polar-personal-access-token",
		Description:  "Polar personal access token.",
		Regex:        utils.GenerateUniqueTokenRegex(`polar_pat_[A-Za-z0-9_-]{20,100}`, false),
		Keywords:     []string{"polar_pat_"},
		ValidateExpr: polarUserTokenValidateExpr,
		Filter:       utils.MinEntropy(3.5),
	}

	// validate
	tps := []string{
		"POLAR_ACCESS_TOKEN=polar_pat_" + secrets.NewSecretWithEntropy(`[A-Za-z0-9_-]{40}`, 3.5),
	}
	fps := polarTokenFalsePositives("polar_pat_")
	return utils.Validate(r, tps, fps)
}

func PolarOAuthAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:       "polar-oauth-access-token",
		Description:  "Polar OAuth access token.",
		Regex:        utils.GenerateUniqueTokenRegex(`polar_at_[A-Za-z0-9_-]{20,100}`, false),
		Keywords:     []string{"polar_at_"},
		ValidateExpr: polarUserTokenValidateExpr,
		Filter:       utils.MinEntropy(3.5),
	}

	// validate
	tps := []string{
		"POLAR_ACCESS_TOKEN=polar_at_" + secrets.NewSecretWithEntropy(`[A-Za-z0-9_-]{40}`, 3.5),
	}
	fps := polarTokenFalsePositives("polar_at_")
	return utils.Validate(r, tps, fps)
}

func polarTokenFalsePositives(prefix string) []string {
	return []string{
		prefix + "short",
		prefix + "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	}
}
