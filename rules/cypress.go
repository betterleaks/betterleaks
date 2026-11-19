package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "cypress-project-id",
	Confidence:  "medium",
	Description: "Detected a Cypress project ID, used as an identifier alongside a Cypress record key.",
	Regex:       rulebuilder.Assignment([]string{"cypress"}, `[a-z0-9]{6}`),
	Keywords:    []string{"cypress"},
	SkipReport:  true,
	FilterExpr:  `entropy(finding["secret"]) <= 2.0`,
	Tests: []config.RuleTest{
		rulebuilder.MatchComponent("shape 1", `cypress = "drex1b"`, `drex1b`),
		rulebuilder.NoMatchComponent("near miss 1", `cypress = "titrk"`),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "cypress-record-key",
	Confidence:  "medium",
	Description: "Detected a Cypress record key, which may allow unauthorized recording and cancellation of test runs in Cypress Cloud.",
	Regex:       rulebuilder.Assignment([]string{"cypress"}, `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
	Keywords:    []string{"cypress"},
	Components:  []config.Component{{RuleID: "cypress-project-id", Optional: true, Within: "5L"}},
	ValidateExpr: `(components["cypress-project-id"]?.secret ?? "") == "" ? {"result": "needs_validation", "reason": "validation needs the cypress-project-id value set beside the key"} : (
let r = http.post("https://api.cypress.io/runs/complete", {"Content-Type": "application/json", "User-Agent": "Go-http-client/1.1"}, "{\"projectId\": \"" + (components["cypress-project-id"]?.secret ?? "") + "\", \"recordKey\": \"" + finding["secret"] + "\", \"runNumber\": \"not-a-number\"}");
(r.status in [422]) ? {"result": "valid"} :
(r.status in [401]) ? {"result": "invalid"} :
validate.unknown(r)
)`,
	FilterExpr: `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		{
			Name:   "shape 1",
			Input:  "cypress = \"824fef2e-8faa-16ab-381c-ebf454d288ac\"\ncypress = \"drex1b\"",
			Expect: []config.ExpectedFinding{{Secret: "824fef2e-8faa-16ab-381c-ebf454d288ac", ComponentSets: []map[string]string{{"cypress-project-id": "drex1b"}}}},
		},
		rulebuilder.Match("shape 1 alone", `cypress = "824fef2e-8faa-16ab-381c-ebf454d288ac"`, `824fef2e-8faa-16ab-381c-ebf454d288ac`),
		rulebuilder.NoMatch("near miss 1", `cypress = "972e2bd6-f664-539f-6586-3afee786221"`),
	},
})
