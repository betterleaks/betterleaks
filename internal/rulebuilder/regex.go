package rulebuilder

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Token matches a credential with a distinctive format, such as a fixed
// prefix, bounded by the standard token delimiters. A leading (?i) makes the
// whole pattern case-insensitive.
func Token(pattern string) string {
	pattern, insensitive := strings.CutPrefix(pattern, "(?i)")
	return uniqueTokenRegex(pattern, insensitive)
}

// Assignment matches a credential assigned to a name containing one of names,
// such as ACME_SECRET = "...". Names are case-insensitive regex fragments. A
// leading (?i) makes the value pattern case-insensitive too.
func Assignment(names []string, pattern string) string {
	pattern, insensitive := strings.CutPrefix(pattern, "(?i)")
	return semiGenericRegex(names, pattern, insensitive)
}

// Domain matches a credential passed as a URL query parameter on one of
// domains, or a subdomain of one. Domains and params are literals. The host
// is case-insensitive; parameter names are case-sensitive. pattern is the
// secret and the only capture; a leading (?i) applies to the secret alone.
// It must not match "\", "&", or ";", which end the secret. within is the
// maximum number of characters (port, path, earlier parameters) between the
// domain and the "?" or ampersand that introduces the parameter.
func Domain(domains, params []string, pattern string, within int) string {
	if hasBlank(domains) || hasBlank(params) || pattern == "" {
		panic("rulebuilder.Domain: domains, params, and pattern must be non-empty")
	}
	if within < 0 || within > 1000 { // 1000 is the regexp repeat limit
		panic("rulebuilder.Domain: within must be between 0 and 1000")
	}
	return domainRegex(domains, params, pattern, within)
}

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

    // A secret ends at a quote, whitespace, a closer, an escaped newline, or
	// the end of the text.
	secretTerminator = `\\?['"\x60]|[\s;)]|\\[nr]|$`
	secretSuffix     = `)(?:` + secretTerminator + `)`
    // A query value also ends at "&", "#", "%" (a percent-encoded delimiter),
	// trailing punctuation, or a closing bracket. 
	// Assume that secrets in query values contain no "\", "&", ";", or "%", 
	// so a single "\", "&", or "%" also covers "&amp;", "\u0026", and "%26".
	domainSecretSuffix = `)(?:` + secretTerminator + `|[&#\\%.,/<>\]}])`

	// domain boundaries. The character before the domain ends the previous
	// hostname label, so notgoogle.com and foo-google.com do not match.
	// The host is case-insensitive.
	domainPrefix = `(?:^|[^A-Za-z0-9-])(?i:`
	// The character after the domain is "?", or ":", "/", "?", "\" (a JSON
	// escape) starting a port or path, so google.com.example.io does not match. 
	// The gap never crosses whitespace, quotes, or into the fragment.
	domainGapPrefix = `)(?:\?|[:/?\\][^\s"'<>#]{0,`
	// The parameter follows "?" or "&", including "&amp;" (HTML) and
	// "\u0026" (JSON written by Go's encoding/json). 
	domainGapSuffix   = `}(?:\?|&(?:amp;)?|\\u0026))(?:`
	domainParamSuffix = `)=(`
)

func semiGenericRegex(identifiers []string, secretRegex string, isCaseInsensitive bool) string {
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
	return sb.String()
}

func writeIdentifiers(sb *strings.Builder, identifiers []string) {
	sb.WriteString(identifierPrefix)
	sb.WriteString(strings.Join(identifiers, "|"))
	sb.WriteString(identifierSuffix)
}

func uniqueTokenRegex(secretRegex string, isCaseInsensitive bool) string {
	var sb strings.Builder
	if isCaseInsensitive {
		sb.WriteString(caseInsensitive)
	}
	sb.WriteString(secretPrefixUnique)
	sb.WriteString(secretRegex)
	sb.WriteString(secretSuffix)
	return sb.String()
}

func domainRegex(domains, params []string, secretRegex string, within int) string {
	var sb strings.Builder
	sb.WriteString(domainPrefix)
	writeLiterals(&sb, domains)
	sb.WriteString(domainGapPrefix)
	sb.WriteString(strconv.Itoa(within))
	sb.WriteString(domainGapSuffix)
	writeLiterals(&sb, params)
	sb.WriteString(domainParamSuffix)
	sb.WriteString(secretRegex)
	sb.WriteString(domainSecretSuffix)
	return sb.String()
}

// writeLiterals writes values as a regex alternation of literals.
func writeLiterals(sb *strings.Builder, values []string) {
	for i, v := range values {
		if i > 0 {
			sb.WriteByte('|')
		}
		sb.WriteString(regexp.QuoteMeta(v))
	}
}

func hasBlank(values []string) bool {
	return len(values) == 0 || slices.Contains(values, "")
}