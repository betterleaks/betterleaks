package rulebuilder

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/ruletest"
	"github.com/betterleaks/betterleaks/v2/regexp"
	"github.com/betterleaks/betterleaks/v2/regexp/re2"
)

var engines = []regexp.Engine{regexp.Stdlib{}, re2.RE2{}}

func TestConfigRequiresRules(t *testing.T) {
	// This package's tests don't import the rules package.
	_, err := Config()
	require.ErrorContains(t, err, "no rules registered")
}

func TestCheckRule(t *testing.T) {
	require.NoError(t, checkRule(config.Rule{ID: "acme", Description: "Acme API key", Keywords: []string{"acme", "acme_"}}))
	require.ErrorContains(t, checkRule(config.Rule{ID: "acme", Description: "TODO: Detected a ..."}), "description still starts with TODO")
	require.ErrorContains(t, checkRule(config.Rule{ID: "acme", Keywords: []string{"ACME"}}), `keyword "ACME" must be lowercase`)
	require.ErrorContains(t, checkRule(config.Rule{ID: "acme", Keywords: []string{"acme", "acme"}}), `duplicate keyword "acme"`)
}

// TestTokenContexts checks the shared regex wrappers once across common
// assignment syntaxes, so individual rules only need to test their format.
func TestTokenContexts(t *testing.T) {
	const secret = "tok_Zx8kQ2mP4vR7tY1wB5nC9dF3gH6jK0Lq"
	for _, tc := range []struct {
		name  string
		regex string
	}{
		{"Token", Token(`tok_[A-Za-z0-9]{32}`)},
		{"Assignment", Assignment([]string{"acme"}, `tok_[A-Za-z0-9]{32}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := baseConfig()
			cfg.Rules = []config.Rule{{ID: "wrapper", Regex: tc.regex, Keywords: []string{"tok_"}}}
			for _, engine := range engines {
				runner, err := ruletest.New(cfg, engine)
				require.NoError(t, err)
				for name, context := range assignmentContexts {
					input := strings.NewReplacer("{i}", "acme", "{I}", "ACME", "{s}", secret).Replace(context)
					cfg.Rules[0].Tests = append(cfg.Rules[0].Tests[:0], Match(name, input, secret))
					failures, err := runner.Run(t.Context(), cfg.Rules[0])
					require.NoError(t, err)
					for _, failure := range failures {
						t.Errorf("%s %s: %v\ninput: %s", engine.Version(), failure.Test, failure.Err, input)
					}
				}
			}
		})
	}
}

// assignmentContexts are common ways a credential is assigned to a name.
// See: https://github.com/gitleaks/gitleaks/issues/1222
var assignmentContexts = map[string]string{
	// Configuration
	// INI
	"ini - quoted1":   "{i}Token=\"{s}\"",
	"ini - quoted2":   "{i}Token = \"{s}\"",
	"ini - unquoted1": "{i}Token={s}",
	"ini - unquoted2": "{i}Token = {s}",
	// JSON
	"json - string": "{\n    \"{i}_token\": \"{s}\"\n}",
	// TODO: "json - escaped string": "\\{\n    \\\"{i}_token\\\": \\\"{s}\\\"\n\\}",
	// TODO: "json - string key/value": "{\n    \"name\": \"{i}_token\",\n    \"value\": \"{s}\"\n}",
	"json - escaped newline in string": `{"config.ini": "{I}_TOKEN={s}\nBACKUP_ENABLED=true"}`,
	// XML
	// TODO: "xml - element":           "<{i}Token>{s}</{i}Token>",
	"xml - element multiline": "<{i}Token>\n    {s}\n</{i}Token>",
	// TODO: "xml - attribute": "<entry name=\"{i}Token\" value=\"{s}\" />",
	// TODO: "xml - key/value elements": "<entry>\n  <name=\"{i}Token\" />\n  <value=\"{s}\" />\n</entry>",
	// YAML
	"yaml - singleline - unquoted":     "{i}_token: {s}",
	"yaml - singleline - single quote": "{i}_token: '{s}'",
	"yaml - singleline - double quote": "{i}_token: \"{s}\"",
	// TODO: "yaml - multiline - literal":       "{i}_token: |\n  {s}",
	// TODO: "yaml - multiline - folding":       "{i}_token: >\n  {s}",
	// "": "",

	// Programming Languages
	"C#":             `string {i}Token = "{s}";`,
	"go - normal":    `var {i}Token string = "{s}"`,
	"go - short":     `{i}Token := "{s}"`,
	"go - backticks": "{i}Token := `{s}`",
	"java":           "String {i}Token = \"{s}\";",
	// TODO: "java - escaped quotes": `config.put("sasl.jaas.config", "org.apache.kafka.common.security.plain.PlainLoginModule required username=\"JDOE35\" {i}Token=\"{s}\""`,
	// TODO:"kotlin - type":         "var {i}Token: string = \"{s}\"",
	"kotlin - notype":     "var {i}Token = \"{s}\"",
	"php - string concat": `${i}Token .= "{s}"`,
	// TODO: "php - null coalesce":   `${i}Token ??= "{s}"`,
	"python - single quote": "{i}Token = '{s}'",
	"python - double quote": `{i}Token = "{s}"`,
	// "": "",

	// Miscellaneous
	// TODO: "url - basic auth":      `https://{i}:{s}@example.com/`,
	// TODO: "url - query parameter": "https://example.com?{i}Token={s}&fooBar=baz",
	// TODO: "comment - slash": "//{s} is the password",
	// TODO: "comment - slash multiline": "/*{s} is the password",
	// TODO: "comment - hashtag":     "#{s} is the password",
	// TODO: "comment - semicolon":     ";{s} is the password",
	// TODO: "csv - unquoted": `{i}Token,{s},`,
	"misc - comma operator": `System.setProperty("{I}_TOKEN", "{s}")`,
	// TODO: "misc - comma suffix": `environmentVariables = {PATH=/usr/local/bin, ENV=/etc/bashrc, {I}_PASSWORD={s}, LC_CTYPE=en_CA.UTF-8},`, // Spotted in `./Library/Logs/gradle-kotlin-dsl-resolver-xxxx.log`
	"logstash": "  \"{i}Token\" => \"{s}\"",
	// TODO: "sql - tabular":      "|{s}|",
	// TODO: "sql":      "",

	// Makefile
	// See: https://github.com/gitleaks/gitleaks/pull/1191
	"make - recursive assignment":       "{i}_TOKEN = \"{s}\"",
	"make - simple assignment":          "{i}_TOKEN := \"{s}\"",
	"make - shell assignment":           "{i}_TOKEN ::= \"{s}\"",
	"make - evaluated shell assignment": "{i}_TOKEN :::= \"{s}\"",
	"make - conditional assignment":     "{i}_TOKEN ?= \"{s}\"",
	// TODO: "make - append":                     "{i}_TOKEN += \"{s}\"",

	// "": "",
}
