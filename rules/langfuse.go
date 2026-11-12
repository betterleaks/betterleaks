package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "langfuse-public-key.1",
	Confidence:  "high",
	Description: "Langfuse public key, used as a component of the Langfuse secret-key composite rule.",
	Regex:       rulebuilder.Token(`pk-lf-` + uuidPattern()),
	Keywords:    []string{"pk-lf-"},
	SkipReport:  true,
	FilterExpr:  rulebuilder.MinEntropy(3.0),
	Tests: []config.RuleTest{
		rulebuilder.MatchComponent("true positive 1", "LANGFUSE_PUBLIC_KEY=pk-lf-1f7b169c-1f7b-1f7b-1f7b-1f7b169c846f", "pk-lf-1f7b169c-1f7b-1f7b-1f7b-1f7b169c846f"),
		rulebuilder.NoMatchComponent("false positive 1", "LANGFUSE_PUBLIC_KEY=pk-lf-00000000-0000-0000-0000-000000000000"),
		rulebuilder.NoMatchComponent("false positive 2", "LANGFUSE_PUBLIC_KEY=pk-lf-short"),
	},
})

// Langfuse also supports several cloud regions and self-hosted instances.
// The EU cloud request can prove a matching pair valid; non-success remains
// unknown rather than rejecting credentials issued for another host.
var _ = rulebuilder.Add(config.Rule{
	ID:          "langfuse-secret-key.1",
	Confidence:  "high",
	Description: "Langfuse secret key, which authenticates project API access when paired with its public key.",
	Regex:       rulebuilder.Token(`sk-lf-` + uuidPattern()),
	Keywords:    []string{"sk-lf-"},
	Components: []config.Component{
		{RuleID: "langfuse-public-key.1", Within: "5L"},
	},
	ValidateExpr: `let r = http.get("https://cloud.langfuse.com/api/public/projects", {
    "Authorization": "Basic " + base64.encode(bytes((components["langfuse-public-key.1"]?.secret ?? "") + ":" + finding["secret"])),
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : validate.unknown(r)`,
	FilterExpr: rulebuilder.MinEntropy(3.0),
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Input: "LANGFUSE_SECRET_KEY=sk-lf-1f7b169c-1f7b-1f7b-1f7b-1f7b169c846f\nLANGFUSE_PUBLIC_KEY=pk-lf-1f7b169c-1f7b-1f7b-1f7b-1f7b169c846f",
			Expect: []config.ExpectedFinding{
				{Secret: "sk-lf-1f7b169c-1f7b-1f7b-1f7b-1f7b169c846f", ComponentSets: []map[string]string{{"langfuse-public-key.1": "pk-lf-1f7b169c-1f7b-1f7b-1f7b-1f7b169c846f"}}},
			},
		},
		rulebuilder.NoMatch("false positive 1", "LANGFUSE_SECRET_KEY=sk-lf-00000000-0000-0000-0000-000000000000"),
		rulebuilder.NoMatch("false positive 2", "LANGFUSE_SECRET_KEY=sk-lf-short"),
	},
})

func uuidPattern() string {
	return `[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`
}
