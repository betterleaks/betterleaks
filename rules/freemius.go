package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "freemius-secret-key",
	Confidence:  "medium",
	Description: "Detected a Freemius secret key, potentially exposing sensitive information.",
	Regex:       `(?i)["']secret_key["']\s*=>\s*["'](sk_[\S]{29})["']`,
	Keywords:    []string{"secret_key"},
	Path:        `(?i)\.php$`,
	Tests: []config.RuleTest{
		{
			Name:       "Invalid: file extension, should validate only .php files",
			Input:      "$config = array(\n\t\t\t\"secret_key\" => \"sk_ubb4yN3mzqGR2x8#P7r5&@*xC$utE\",\n\t\t);",
			Attributes: map[string]string{"path": "file.php"},
			Expect: []config.ExpectedFinding{
				{Secret: "sk_ubb4yN3mzqGR2x8#P7r5&@*xC$utE"},
			},
		},
		{
			Name:       "Invalid format: missing quotes around the key value",
			Input:      "$config = array(\n\t\t\t\"secret_key\" => sk_abcdefghijklmnopqrstuvwxyz123,\n\t\t);",
			Attributes: map[string]string{"path": "bar.php"},
			Expect:     []config.ExpectedFinding{},
		},
		{
			Name:       "Invalid: different key name",
			Input:      "$config = array(\n\t\t\t\"other_key\" => \"sk_abcdefghijklmnopqrstuvwxyz123\",\n\t\t);",
			Attributes: map[string]string{"path": "baz.php"},
			Expect:     []config.ExpectedFinding{},
		},
		{
			Name:       "Invalid: file extension, should validate only .php files 2",
			Input:      "$config = array(\n\t\t\t\"secret_key\" => \"sk_ubb4yN3mzqGR2x8#P7r5&@*xC$utE\",\n\t\t);",
			Attributes: map[string]string{"path": "foo.html"},
			Expect:     []config.ExpectedFinding{},
		},
		{
			Name:       "Invalid format: missing quotes around `secret_key`",
			Input:      "$config = array(\n\t\t\tsecret_key => \"sk_abcdefghijklmnopqrstuvwxyz123\",\n\t\t);",
			Attributes: map[string]string{"path": "foo.php"},
			Expect:     []config.ExpectedFinding{},
		},
	},
})
