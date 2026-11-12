package rulebuilder

import "strings"

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
	secretSuffix       = `)(?:\\?['"\x60]|[\s;)]|\\[nr]|$)`
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
