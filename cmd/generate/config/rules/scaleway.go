package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func ScalewaySecretKey() *config.Rule {
	r := config.Rule{
		RuleID:      "scaleway-secret-key",
		Description: "Identified a standalone Scaleway Secret Key. This can be used to authenticate API requests.",
		Regex: utils.GenerateSemiGenericRegex(
			[]string{`(?:scaleway|scw).{0,20}?(?:secret|token)`},
			utils.Hex8_4_4_4_12(),
			true,
		),
		Entropy:  3,
		Keywords: []string{"scaleway", "scw"},
		ValidateCEL: `cel.bind(r,
  http.get("https://api.scaleway.com/instance/v1/zones/fr-par-1/servers", {
    "X-Auth-Token": secret,
    "Accept": "application/json"
  }),
  r.status in [200, 403] ? {
    "result": "valid",
    "permission_status": r.status == 200 ? "Active" : "Restricted but still valid (403)",
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	}

	secret := secrets.NewSecretWithEntropy(utils.Hex8_4_4_4_12(), 3)
	tps := []string{
		`scaleway_secret = "` + secret + `"`,
		`scw_token: "` + secret + `"`,
		`SCW_SECRET := "` + secret + `"`,
	}
	fps := []string{
		`scaleway_secret = "not-a-uuid"`,
		`scw_token = "12345678-1234-1234-1234-12345678901"`,
	}

	return utils.Validate(r, tps, fps)
}
