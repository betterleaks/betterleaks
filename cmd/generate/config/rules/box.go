package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
)

func BoxAPIAccessToken() *config.Rule {
	r := config.Rule{
		RuleID:      "box-api-access-token",
		Description: "Detected a Box API access token, which may expose Box files and account data.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"box"}, utils.AlphaNumeric("32"), true),
		Keywords:    []string{"box_", "box-", "boxt", "boxk", "boxa"},
		ValidateCEL: utils.BearerGetValidationCEL("https://api.box.com/2.0/users/me", "r.body.contains(\"\\\"id\\\"\")"),
		Filter:      utils.MinEntropy(3.5),
	}

	tps := []string{
		`BOX_DEVELOPER_TOKEN="DkXZmsjUKizvL2z0WiaLvMBeQ756XCGG"`,
		`box_access_token = 'A4bC5dE6fG7hI8jK9lM0nO1pQ2rS3tU4'`,
	}
	fps := []string{
		`BOX_DOC_URL="https://developer.box.com"`,
		`sandbox_mode = true`,
	}
	return utils.Validate(r, tps, fps)
}
