package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func FigmaPersonalAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Uncovered a Figma Personal Access Token, which may compromise design assets and team collaboration.",
		RuleID:      "figma-personal-access-token",
		Regex:       utils.GenerateUniqueTokenRegex(`figd_[A-Z0-9_-]{38,42}`, true),
		Entropy:     3.5,
		Keywords:    []string{"figd_"},
		ValidateCEL: `cel.bind(r,
  http.get("https://api.figma.com/v1/me", {
    "X-Figma-Token": secret
  }),
  r.status == 200 && !r.body.contains("Invalid token") ? {
    "result": "valid",
    "email": r.json.?email.orValue(""),
    "handle": r.json.?handle.orValue(""),
    "id": r.json.?id.orValue("")
  } : r.status in [401, 403] || r.body.contains("Invalid token") ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("figma", secrets.NewSecretWithEntropy(`figd_[A-Z0-9_-]{38,42}`, 3.5))
	tps = append(tps,
		`figma pat = figd_rh1234567890123456789012345678901234abcd`,
		`figma access token: figd_1234567890123456789012345678901234abcdef`,
	)
	return utils.Validate(r, tps, nil)
}

func FigmaPersonalAccessHeaderToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Uncovered a Figma Personal Access Token in a header, which may compromise design assets and team collaboration.",
		RuleID:      "figma-personal-access-header-token",
		Regex:       utils.GenerateSemiGenericRegex([]string{"x-figma-token", "xfigmatoken", "x_figma_token"}, `[0-9A-F]{4}-[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}`, true),
		Keywords:    []string{"X-Figma-Token", "xfigmatoken", "x_figma_token"},
		ValidateCEL: `cel.bind(r,
  http.get("https://api.figma.com/v1/me", {
    "X-Figma-Token": secret
  }),
  r.status == 200 && !r.body.contains("Invalid token") ? {
    "result": "valid",
    "email": r.json.?email.orValue(""),
    "handle": r.json.?handle.orValue(""),
    "id": r.json.?id.orValue("")
  } : r.status in [401, 403] || r.body.contains("Invalid token") ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("x-figma-token", secrets.NewSecret(`[0-9A-F]{4}-[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}`))
	tps = append(tps,
		`--header='X-Figma-Token: 1394-0ca7a5be-8e22-40ee-8c40-778d41ab2313'`,
	)
	return utils.Validate(r, tps, nil)
}
