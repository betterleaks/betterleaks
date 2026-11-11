package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "langfuse-public-key.1",
	Confidence:  "high",
	Description: "Langfuse public key, used as a component of the Langfuse secret-key composite rule.",
	Regex:       Token(`pk-lf-` + uuidPattern()),
	Keywords:    []string{"pk-lf-"},
	SkipReport:  true,
	FilterExpr:  MinEntropy(3.0),
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Mode:  "match",
			Input: "LANGFUSE_PUBLIC_KEY=pk-lf-1f7b169c-1f7b-1f7b-1f7b-1f7b169c846f",
			Expect: []config.ExpectedFinding{
				{Secret: "pk-lf-1f7b169c-1f7b-1f7b-1f7b-1f7b169c846f"},
			},
		},
		{
			Name:   "false positive 1",
			Mode:   "match",
			Input:  "LANGFUSE_PUBLIC_KEY=pk-lf-00000000-0000-0000-0000-000000000000",
			Expect: []config.ExpectedFinding{},
		},
		{
			Name:   "false positive 2",
			Mode:   "match",
			Input:  "LANGFUSE_PUBLIC_KEY=pk-lf-short",
			Expect: []config.ExpectedFinding{},
		},
	},
})

// Langfuse also supports several cloud regions and self-hosted instances.
// The EU cloud request can prove a matching pair valid; non-success remains
// unknown rather than rejecting credentials issued for another host.
var _ = Add(config.Rule{
	ID:          "langfuse-secret-key.1",
	Confidence:  "high",
	Description: "Langfuse secret key, which authenticates project API access when paired with its public key.",
	Regex:       Token(`sk-lf-` + uuidPattern()),
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
	FilterExpr: MinEntropy(3.0),
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Input: "LANGFUSE_SECRET_KEY=sk-lf-1f7b169c-1f7b-1f7b-1f7b-1f7b169c846f\nLANGFUSE_PUBLIC_KEY=pk-lf-1f7b169c-1f7b-1f7b-1f7b-1f7b169c846f",
			Expect: []config.ExpectedFinding{
				{Secret: "sk-lf-1f7b169c-1f7b-1f7b-1f7b-1f7b169c846f", ComponentSets: []map[string]string{{"langfuse-public-key.1": "pk-lf-1f7b169c-1f7b-1f7b-1f7b-1f7b169c846f"}}},
			},
		},
		NoMatch("false positive 1", "LANGFUSE_SECRET_KEY=sk-lf-00000000-0000-0000-0000-000000000000"),
		NoMatch("false positive 2", "LANGFUSE_SECRET_KEY=sk-lf-short"),
	},
})

func uuidPattern() string {
	return Hex("8") + `-` + Hex("4") + `-` + Hex("4") + `-` + Hex("4") + `-` + Hex("12")
}
