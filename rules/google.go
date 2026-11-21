package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "google-oauth-client-id",
	Confidence:  "high",
	Description: "Google OAuth Client ID",
	Regex:       rulebuilder.Token(`[0-9]{12,}-[a-z0-9]{32}\.apps\.googleusercontent\.com`),
	Keywords:    []string{".apps.googleusercontent.com"},
	SkipReport:  true,
	FilterExpr:  `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		rulebuilder.MatchComponent("shape 1", `token = "49913430651650484780635-mrtsswj6bqljfs1isz3fdk7k37ipxa56.apps.googleusercontent.com"`, `49913430651650484780635-mrtsswj6bqljfs1isz3fdk7k37ipxa56.apps.googleusercontent.com`),
		rulebuilder.NoMatchComponent("near miss 1", `token = "4612487091656323394032242795939392985593825341063-a4xxdllrba0xt7zqiya8kjobxyrkal0.apps.googleusercontent.com"`),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "google-client-secret",
	Confidence:  "high",
	Description: "Detected a Google OAuth client secret, which may allow unauthorized API requests and token acquisition when paired with an OAuth client ID.",
	Regex:       rulebuilder.Token(`GOCSPX-[A-Za-z0-9_-]{28}`),
	Keywords:    []string{"gocspx-"},
	Components:  []config.Component{{RuleID: "google-oauth-client-id", Optional: true, Within: "10L"}},
	ValidateExpr: `(components["google-oauth-client-id"]?.secret ?? "") == "" ? {"result": "needs_validation", "reason": "validation needs the google-oauth-client-id value set beside the key"} : (
let r = http.post("https://oauth2.googleapis.com/token", {"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Go-http-client/1.1"}, "client_id=" + strings.urlQueryEscape((components["google-oauth-client-id"]?.secret ?? "")) + "&client_secret=" + strings.urlQueryEscape(finding["secret"]) + "&grant_type=refresh_token&refresh_token=probe_check_dummy_token");
(r.status in [400] && (r.json?.error == "invalid_grant")) ? {"result": "valid"} :
(r.status in [401] && (r.json?.error == "invalid_client")) ? {"result": "invalid"} :
validate.unknown(r)
)`,
	FilterExpr: `entropy(finding["secret"]) <= 3.5`,
	Tests: []config.RuleTest{
		{
			Name:   "shape 1",
			Input:  "token = \"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\"\ntoken = \"49913430651650484780635-mrtsswj6bqljfs1isz3fdk7k37ipxa56.apps.googleusercontent.com\"",
			Expect: []config.ExpectedFinding{{Secret: "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", ComponentSets: []map[string]string{{"google-oauth-client-id": "49913430651650484780635-mrtsswj6bqljfs1isz3fdk7k37ipxa56.apps.googleusercontent.com"}}}},
		},
		rulebuilder.Match("shape 1 alone", `token = "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"`, `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`),
		rulebuilder.NoMatch("near miss 1", `token = "GOCSPX-8ZQvd-GYopQ5lwilVRN1_DpySH9"`),
	},
})
