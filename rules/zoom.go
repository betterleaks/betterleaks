package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "zoom-client-id",
	Confidence:  "medium",
	Description: "Detected a Zoom client ID, used alongside a client secret to authenticate Zoom API requests.",
	Regex:       rulebuilder.Assignment([]string{"zoom"}, `[A-Za-z0-9_\-]{21,22}`),
	Keywords:    []string{"zoom"},
	SkipReport:  true,
	FilterExpr:  `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		rulebuilder.MatchComponent("shape 1", `zoom = "w0tjTpYpsv3rtQ3P0ODDn"`, `w0tjTpYpsv3rtQ3P0ODDn`),
		rulebuilder.NoMatchComponent("near miss 1", `zoom = "_F3jKUeS9x-SGPxVWgtl"`),
		rulebuilder.NoMatchComponent("near miss 2", `zoom = "Or9WPXhg0cnY8YsBQ3KX5_b"`),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "zoom-client-secret",
	Confidence:  "medium",
	Description: "Detected a Zoom client secret, which may allow unauthorized access to Zoom APIs when paired with a client ID.",
	Regex:       rulebuilder.Assignment([]string{"zoom"}, `[A-Za-z0-9]{32}`),
	Keywords:    []string{"zoom"},
	Components:  []config.Component{{RuleID: "zoom-client-id", Optional: true, Within: "5L"}},
	ValidateExpr: `(components["zoom-client-id"]?.secret ?? "") == "" ? {"result": "needs_validation", "reason": "validation needs the zoom-client-id value set beside the key"} : (
let r = http.post("https://zoom.us/oauth/token", {"Content-Type": "application/x-www-form-urlencoded", "Authorization": "Basic " + base64.encode(bytes((components["zoom-client-id"]?.secret ?? "") + ":" + finding["secret"])), "User-Agent": "Go-http-client/1.1"}, "grant_type=client_credentials");
(r.status in [200]) ? {
    "result": "valid",
    "analysis": {
      "scopes": string(r.json?.scope ?? ""),
    }
  } :
(r.status in [400] && (r.json?.reason == "The app has been disabled by the developer")) ? {"result": "valid"} :
(r.status in [400] && (r.json?.reason == "Invalid client_id or client_secret")) ? {"result": "invalid"} :
validate.unknown(r)
)`,
	FilterExpr: `entropy(finding["secret"]) <= 3.5`,
	Tests: []config.RuleTest{
		{
			Name:   "shape 1",
			Input:  "zoom = \"pRFwiuYTaxYX44MsXXi9ViqakhhXiYje\"\nzoom = \"w0tjTpYpsv3rtQ3P0ODDn\"",
			Expect: []config.ExpectedFinding{{Secret: "pRFwiuYTaxYX44MsXXi9ViqakhhXiYje", ComponentSets: []map[string]string{{"zoom-client-id": "w0tjTpYpsv3rtQ3P0ODDn"}}}},
		},
		rulebuilder.Match("shape 1 alone", `zoom = "pRFwiuYTaxYX44MsXXi9ViqakhhXiYje"`, `pRFwiuYTaxYX44MsXXi9ViqakhhXiYje`),
		rulebuilder.NoMatch("near miss 1", `zoom = "nDhcRLcrCUhbtB4cZQawJvLB3lpE85M"`),
		rulebuilder.NoMatch("near miss 2", `zoom = "on45iHZGt7KMkr4iYGV53RTCbD3DPFBtuq527"`),
	},
})
