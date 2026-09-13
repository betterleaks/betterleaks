// == WARNING ==
// These functions are used to generate GitLeak's default config.
// You are free to use these in your own project, HOWEVER, no API stability is guaranteed.

package utils

import (
	"fmt"
	"strings"

	"github.com/betterleaks/betterleaks/regexp"
)

const (
	// case insensitive prefix
	caseInsensitive = `(?i)`

	// identifier prefix (just an ignore group)
	identifierCaseInsensitivePrefix = `(?i:`
	identifierCaseInsensitiveSuffix = `)`
	identifierPrefix                = `(?:`
	identifierSuffix                = `)(?:[ \t\w.-]{0,20})[\s'"]{0,3}`

	// commonly used assignment operators or function call
	//language=regexp
	operator = `(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)`

	// boundaries for the secret
	secretPrefixUnique = `\b(`
	secretPrefix       = `[\x60'"\s=]{0,5}(`
	secretSuffix       = `)(?:\\?['"\x60]|[\s;]|\\[nr]|$)`

	// secretSuffixProse also accepts the punctuation that ends a token in running
	// text. It is opt-in rather than folded into secretSuffix because the safe
	// terminator set depends on the token body: allowing `.` after a body that can
	// itself contain dots reintroduces suffix confusion. auth0-domain, whose body
	// is a dotted domain, would match `example.auth0.com.evil.example`, and
	// infracost-api-token would match a cache-busted `.png` filename. Only use
	// this for a body that cannot contain these characters. See issue #356.
	//
	// The punctuation must itself be followed by whitespace or end of input, so
	// that it is punctuation ending a token in running text rather than a
	// separator inside a longer string: `<token>.` matches and `<token>.png`
	// does not. A closing quote counts as that boundary too, so a token ending a
	// sentence inside a JSON or YAML string is still found. A run is allowed, so
	// `(<token>).` matches too. The cost is that
	// a spaceless list such as `<token>,<token>` is not matched, which the
	// shared secretSuffix does not match either.
	secretSuffixProse = `)(?:\\?['"\x60]|[\s;]|[.,:!?)\]}>]+(?:\\?['"\x60]|\s|$)|\\[nr]|$)`
)

func GenerateSemiGenericRegex(identifiers []string, secretRegex string, isCaseInsensitive bool) *regexp.Regexp {
	var sb strings.Builder
	// The identifiers should always be case-insensitive.
	// This is inelegant but prevents an extraneous `(?i:)` from being added to the pattern; it could be removed.
	if isCaseInsensitive {
		sb.WriteString(caseInsensitive)
		writeIdentifiers(&sb, identifiers)
	} else {
		sb.WriteString(identifierCaseInsensitivePrefix)
		writeIdentifiers(&sb, identifiers)
		sb.WriteString(identifierCaseInsensitiveSuffix)
	}
	sb.WriteString(operator)
	sb.WriteString(secretPrefix)
	sb.WriteString(secretRegex)
	sb.WriteString(secretSuffix)
	return regexp.MustCompile(sb.String())
}

func MergeRegexps(regexps ...*regexp.Regexp) *regexp.Regexp {
	patterns := make([]string, len(regexps))

	for i, r := range regexps {
		patterns[i] = r.String()
	}

	return regexp.MustCompile(strings.Join(patterns, "|"))
}

func writeIdentifiers(sb *strings.Builder, identifiers []string) {
	sb.WriteString(identifierPrefix)
	sb.WriteString(strings.Join(identifiers, "|"))
	sb.WriteString(identifierSuffix)
}

func GenerateUniqueTokenRegex(secretRegex string, isCaseInsensitive bool) *regexp.Regexp {
	var sb strings.Builder
	if isCaseInsensitive {
		sb.WriteString(caseInsensitive)
	}
	sb.WriteString(secretPrefixUnique)
	sb.WriteString(secretRegex)
	sb.WriteString(secretSuffix)
	return regexp.MustCompile(sb.String())
}

// GenerateUniqueTokenProseRegex is GenerateUniqueTokenRegex with a terminator set
// that also accepts sentence punctuation, so a token at the end of a sentence or
// inside brackets is still detected. Read secretSuffixProse before using it: it is
// only safe for a body that cannot contain `.`, `,`, `)`, `]`, `}` or `>`.
func GenerateUniqueTokenProseRegex(secretRegex string, isCaseInsensitive bool) *regexp.Regexp {
	var sb strings.Builder
	if isCaseInsensitive {
		sb.WriteString(caseInsensitive)
	}
	sb.WriteString(secretPrefixUnique)
	sb.WriteString(secretRegex)
	sb.WriteString(secretSuffixProse)
	return regexp.MustCompile(sb.String())
}

func GenerateSampleSecret(identifier string, secret string) string {
	return fmt.Sprintf("%s_api_token = \"%s\"", identifier, secret)
}

// See: https://github.com/gitleaks/gitleaks/issues/1222
func GenerateSampleSecrets(identifier string, secret string) []string {
	samples := map[string]string{
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

	replacer := strings.NewReplacer(
		"{i}", identifier,
		"{I}", strings.ToUpper(identifier),
		"{s}", secret,
	)
	cases := make([]string, 0, len(samples))
	for _, v := range samples {
		cases = append(cases, replacer.Replace(v))
	}
	return cases
}

func Ptr[T any](v T) *T {
	return &v
}
