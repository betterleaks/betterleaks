package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "cisco-meraki-api-key",
	Confidence:  "high",
	Description: "Cisco Meraki is a cloud-managed IT solution that provides networking, security, and device management through an easy-to-use interface.",
	Regex:       Assignment([]string{`(?-i:[Mm]eraki|MERAKI)`}, `[0-9a-f]{40}`),
	Keywords:    []string{"meraki"},
	ValidateExpr: `let r = http.get("https://api.meraki.com/api/v1/organizations", {
    "X-Cisco-Meraki-API-Key": finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) < 3.3 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("meraki assignment", `merakiToken = "1f7b169c846f218ab552fa82fbf86758bf5c97d2"`, "1f7b169c846f218ab552fa82fbf86758bf5c97d2"),
		NoMatch("low entropy", "meraki: aaaaaaaaaa1111111111bbbbbbbbbb2222222222"),
		NoMatch("invalid case", "meraki-api-key: acdeFf05b1a6d4c890237bf08c5e6e8d2b4d0f2e"),
		NoMatch("invalid character", "meraki: abdefghjk0123456789mnopqrstuvwx12345678"),
		NoMatch("invalid length", "meraki_token = 5cb4a5f04cd412fe946667b17f0129ba17aeb2e0c7b5b7264efcebf7d022bfe2R21"),
		NoMatch("false positive 1", "ReactNativeCameraKit: f15a5a04b0f6dc6073e6db0296e6ef2d8b8d2522"),
	},
})
