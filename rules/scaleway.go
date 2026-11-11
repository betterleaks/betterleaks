package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "scaleway-secret-key",
	Confidence:  "high",
	Description: "Identified a standalone Scaleway Secret Key. This can be used to authenticate API requests.",
	Regex: Assignment(
		[]string{`(?:scaleway|scw).{0,20}?(?:secret|token)`},
		`(?i)`+Hex8_4_4_4_12(),
	),
	FilterExpr: MinEntropy(3),
	Keywords:   []string{"scaleway", "scw"},
	ValidateExpr: `let r = http.get("https://api.scaleway.com/instance/v1/zones/fr-par-1/servers", {
    "X-Auth-Token": secret,
    "Accept": "application/json"
  }); r.status in [200, 403] ? {
    "result": "valid",
    "metadata": {"permission_status": r.status == 200 ? "Active" : "Restricted but still valid (403)"}
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	Tests: []config.RuleTest{
		Match("true positive 1", `scaleway_secret = "1f7b169c-846f-218a-b552-fa82fbf86758"`, "1f7b169c-846f-218a-b552-fa82fbf86758"),
		Match("true positive 2", `scw_token: "1f7b169c-846f-218a-b552-fa82fbf86758"`, "1f7b169c-846f-218a-b552-fa82fbf86758"),
		Match("true positive 3", `SCW_SECRET := "1f7b169c-846f-218a-b552-fa82fbf86758"`, "1f7b169c-846f-218a-b552-fa82fbf86758"),
		NoMatch("false positive 1", `scaleway_secret = "not-a-uuid"`),
		NoMatch("false positive 2", `scw_token = "12345678-1234-1234-1234-12345678901"`),
	},
})
